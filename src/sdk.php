<?php
namespace Albis\Sdk;
if(session_status() != PHP_SESSION_ACTIVE){
    session_start();
}
//timeout in seconds as per albis specification
set_time_limit(120);

/**
* Albis Wrapper class
*/
class Albis{
    /** associative array with credential information
    *     "username" => Albis Username
    *     "password" => Albis Password
    *     "auth0Username" => Auth0-Username
    *     "auth0Password" => Auth0-Password
    *     "realm" => user realm (e.g. TestUsers)
     */
    private $credentials;
    /** stored session token */
    private $localSessionToken;
    /** expiry date of session token, UNIX-Timestamp in seconds */
    private $localSessionTokenExpires;
    private $config;

    /** creates a new Albis-Object.
    *   @param $albisConfig AlbisConfig-Object with base configuration
    *   @param [$credentials] associative array with credential information
    *     "username" => Albis Username
    *     "password" => Albis Password
    *     "auth0Username" => Auth0-Username
    *     "auth0Password" => Auth0-Password
    *     "realm" => user realm (e.g. TestUsers)
    *      optional; in case of boolean false or unset, the SDK will try to parse
    *                the request body for a JSON that includes those fields
    *   @return Albis object
    */
    function __construct($albisConfig, $credentials = false){
        if($credentials !== false){
            $this->credentials = $credentials;
        }else{//try to get credentials from request body
             $body = Albis::getRequestBodyJSONArray();
             $this->credentials = $body;
        }
        $this->localSessionToken = Albis::getStorage('localSessionToken');
        $this->localSessionTokenExpires = Albis::getStorage('localSessionTokenExpires');
        $this->config = $albisConfig;
    }
    
    function setCredentials($credentials){
        $this->credentials = $credentials;
    }

    /** removes cached session token from cache, if it exists
    *   @return void
    */
    function killSessionTokenCache(){
        $this->localSessionToken = null;
        $this->localSessionTokenExpires = null;
        Albis::killStorage('localSessionToken');
    }

    //----------------------------------------------------------------
    //----------------------- sdk functions --------------------------
    //----------------------------------------------------------------

    /** get the Albis token string, either from cache or by requesting a new
    *   one from the Albis endpoint, if $forceRenew is true, no
    *   cached token exists, or current time is after the expiry date
    *   of cached token. This function will automatically cache the token.
    *   @param [$customCredentials] associative array with custom
    *       credentials (for example see constructor) to use for
    *       authorization with Albis endpoint. If unset or false, takes
    *       credentials given in constructor
    *   @param [$forceRenew] force renewal of token, ignore cache
    *   @return string with Albis token
    *   @throws Exception in case of missing credentials or error on
    *           endpoint's side
    */
    function getAlbisToken($customCredentials = false, $forceRenew = false){
        return $this->getTokenArray($customCredentials,$forceRenew,true)['access_token'];
    }
    
     /** get the Albis token, either from cache or by requesting a new
    *   one from the Albis endpoint, if $forceRenew is true, no
    *   cached token exists, or current time is after the expiry date
    *   of cached token
    *   @param [$customCredentials] associative array with custom
    *       credentials (for example see constructor) to use for
    *       authorization with Albis endpoint. If unset or false, takes
    *       credentials given in constructor
    *   @param [$forceRenew] force renewal of token, ignore cache
    *   @param [$saveToStorage] save token to storage
    *   @return associative array with keys acces_token and expires_in
    *   @throws Exception in case of missing credentials or error on
    *           endpoint's side
    */
    function getTokenArray($customCredentials = false, $forceRenew = false, $saveToStorage = false){
        if($customCredentials === false && $this->localSessionToken != null && $this->localSessionTokenExpires != null && $this->localSessionTokenExpires > time() && !$forceRenew){
            return array('access_token'=>$this->localSessionToken,'expires_in'=>$this->localSessionTokenExpires);
        }
        //--- get new token ---
        $mandatoryFieldsArray = ['username','password','auth0Username','auth0Password','realm'];
        $missingFieldsArray = [];
        $sendJSONArray = [];
        $credentials = $this->credentials;
        if($customCredentials !== false){
            $credentials = $customCredentials;
        }
        if($this->credentials == null){
            Albis::error("no credentials sent",4,true);
        }

        foreach($mandatoryFieldsArray as $value){
            if(isset($credentials[$value])){
                $sendJSONArray[$value] = $credentials[$value];
            }else{
                array_push($missingFieldsArray,$value);
            }
        }
        if(sizeof($missingFieldsArray) > 0){
            Albis::error("missing credential fields: " . implode(", ",$missingFieldsArray),4,true);
        }
        //send request and return
        $rsp = $this->sendPost('token',$sendJSONArray);
        Albis::setStorage('localSessionTokenRaw',$rsp);
        $ret = json_decode($rsp,true);
        if(!isset($ret['access_token'])){
            Albis::error("token response doesn't include token: " . $rsp,4,true);
        }
        if(!isset($ret['expires_in'])){
            Albis::error("token response doesn't include expiry: " . $rsp,3,true);
        }
        if($saveToStorage){
            $expiry = time() + $ret['expires_in'];
            $this->setToken($ret['access_token'],$expiry);
        }
        return $ret;
    }
    
    /*
    * saves a token to cache. 
    * @param $tokenString - the token as string
    * @param $expiryUnixTimestamp - expiry unix timestamp (seconds). Will be reduced by config TOKEN_EXPIRY_GRACE_PERIOD  
    **/
    function setToken($tokenString,$expiryUnixTimestamp){
        $this->localSessionToken = $tokenString;
        Albis::setStorage('localSessionToken',$tokenString); 
        $exp = $expiryUnixTimestamp - $this->config->GET_TOKEN_EXPIRY_GRACE_PERIOD();        
        $this->localSessionTokenExpires = $exp;
        Albis::setStorage('localSessionTokenExpires',$exp);
    }

    /** destroys session cache
    *   @return void
    */
    function logout(){
        session_destroy();
    }

    /** change Albis and auth0-password
    *   @param $albisNewPassword new password for albis
    *   @param $auth0NewPassword new auth0 passwort
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function changePassword($albisNewPassword, $auth0NewPassword, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('password',array('auth0NewPassword' => $auth0NewPassword,'albisNewPassword' => $albisNewPassword),$token),$returnType);
    }

    /** send a test request to Albis
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function albisPing($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('ping',[],$token, false, "GET"),$returnType);
    }

    /** send an echo request to Albis
    *   @param $data data to echo back
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function albisEcho($data, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('echo',array("data"=>$data),$token, false, "GET"),$returnType);
    }

    /** find an Application and return its data
    *   @param $id Albis application id
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function findApplication($id, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('application',array("applicationId"=>$id),$token, false, "GET"),$returnType);
    }
    
    /** find a frame application and return its data
    *   @param $id Albis frame application id
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function findFrameApplication($id, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('frame-application',array("applicationId"=>$id),$token, false, "GET"),$returnType);
    }
    
    /** finds all sub applications of the indicated frame application
    *   @param $frameApplicationId id of frame application
    *   @param [$showExternalStatus] (boolean) indicates if applicationStatusTxt with a description of received application status should be attached to the result set
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function findFrameSubApplications($frameApplicationId, $showExternalStatus = false, $returnType = false){
        if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('frame-sub-applications',array("applicationId"=>$frameApplicationId,
                                                                                            "showExternalStatus" => $showExternalStatus
                                                                                            ),$token, false, "GET"),$returnType);
    }

    /** get an Application's status
    *   @param $id Albis application id
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getApplicationStatus($id, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('applications-status',array("applicationId"=>$id),$token, false, "GET"),$returnType);
    }

    /** updates an application
    *   @param $applicationObject object or associative array with application values.
    *   @param {number} $applicationObject.id - application number, which will be updated
    *   @param {boolean}$applicationObject.contactByEmail - is contact by email required
    *   @param {number} $applicationObject.contractType - contract type
    *   @param {number} $applicationObject.downPayment - down payment
    *   @param {string} $applicationObject.iban - iban
    *   @param {Object} $applicationObject.lessee - lessee data
    *   @param {string} $applicationObject.lessee.city - lessee city
    *   @param {string} $applicationObject.lessee.email - lessee email
    *   @param {number} $applicationObject.lessee.legalForm - lessee legal form
    *   @param {string} $applicationObject.lessee.name - lessee name
    *   @param {string} $applicationObject.lessee.phoneNumber - lessee phone number
    *   @param {string} $applicationObject.lessee.street - lessee street
    *   @param {string} $applicationObject.lessee.zipCode - lessee zip code
    *   @param {number} $applicationObject.leaseTerm - lease term (returned from getRates() method)
    *   @param {string} $applicationObject.object - name of the object (80 char max)
    *   @param {number} $applicationObject.paymentMethod - payment method
    *   @param {number} $applicationObject.productGroup - product group
    *   @param {string} $applicationObject.promotionId - lease term (returned from getRates() if conditions matched any promotion)
    *   @param {string} $applicationObject.provision - defines how much commission, retailer wants to receives for each deal. Possible $applicationObject min: 0, max: 5. Default 0
    *   @param {number} $applicationObject.purchasePrice - purchase price (object value)
    *   @param {number} $applicationObject.rate - rate (returned from getRates() method)
    *   @param {string} $applicationObject.reference - application reference (helper for shop employees)
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    */
    function updateApplication($applicationObject, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        $this->setApplicationObjectStandardValues($applicationObject);
        return Albis::formatJsonReturn($this->sendPost('application',json_encode(Albis::utf8ize($applicationObject)),$token, true, "PUT"),$returnType);
    }

    /** saves (inserts) an application
    *   @param $applicationObject object or associative array with application values.
        *   {Object} $applicationObject - An object with application data
    *   {boolean} $applicationObject.contactByEmail - is contact by email required
    *   {number} $applicationObject.contractType - contract type
    *   {number} $applicationObject.downPayment - down payment
    *   {string} $applicationObject.iban - iban
    *   {Object} $applicationObject.lessee - lessee data
    *   {string} $applicationObject.lessee.city - lessee city
    *   {string} $applicationObject.lessee.email - lessee email
    *   {number} $applicationObject.lessee.legalForm - lessee legal form
    *   {string} $applicationObject.lessee.name - lessee name
    *   {string} $applicationObject.lessee.phoneNumber - lessee phone number
    *   {string} $applicationObject.lessee.street - lessee street
    *   {string} $applicationObject.lessee.zipCode - lessee zip code
    *   {Object} $applicationObject.lessee.manager - lessee's manager data
    *   {string} $applicationObject.lessee.manager.birthDate - lessee's manager birth date (format required: "DD.MM.YYYY")
    *   {string} $applicationObject.lessee.manager.city - lessee's manager city
    *   {string} $applicationObject.lessee.manager.firstName - lessee's manager first name
    *   {string} $applicationObject.lessee.manager.lastName - lessee's manager last name
    *   {string} $applicationObject.lessee.manager.salutation - lessee's manager salutation form
    *   {string} $applicationObject.lessee.manager.street - lessee's manager street
    *   {string} $applicationObject.lessee.manager.zipCode - lessee's manager zip code
    *   {number} $applicationObject.leaseTerm - lease term (returned from getRates() method)
    *   {string} $applicationObject.object - name of the object (80 char max)
    *   {number} $applicationObject.paymentMethod - payment method
    *   {number} $applicationObject.productGroup - product group
    *   {string} $applicationObject.promotionId - lease term (returned from getRates() if conditions matched any promotion)
    *   {number} $applicationObject.purchasePrice - purchase price (object value)
    *   {number} $applicationObject.rate - rate (returned from getRates() method)
    *   {number} $applicationObject.rateWithInsurance - rate with insurance (returned from getRates() method)
    *   {string} $applicationObject.reference - application reference (helper for shop employees)
    *   {string} $applicationObject.receiverEndpoint - endpoint address where requests about application/documentation updates should be delivered (optional)
    *   {Object[]} $applicationObject.receiverFailEmails - array of string emails where info about connection with reveiver endpoint should be delivered (optional)
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    */
    function saveApplication($applicationObject, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        Albis::setApplicationObjectStandardValues($applicationObject);
        return Albis::formatJsonReturn($this->sendPost('application',json_encode(Albis::utf8ize($applicationObject)),$token, true, "POST"),$returnType);
    }
    
    /*
    @param values	Object	An object with application data
        [values.contactByEmail]	boolean	indicator that the leasing contract should be sent to the lessee by e-mail after approval. TRUE/FALSE, Default:FALSE (optional)
        values.contractType	number	contract type (result of getContractTypes() method)
        [values.downPayment]	number	down payment (optional)
        [values.iban]	string	IBAN of account to be charged with contract instalments (may be entered with spaces) (optional)
        values.frameApplicationId	number	a frame application id
        values.lessee	Object	lessee data
        values.lessee.city	string	lessee city
        values.lessee.email	string	lessee email
        values.lessee.legalForm	number	lessee legal form
        values.lessee.name	string	lessee name
        values.lessee.phoneNumber	string	lessee phone number
        values.lessee.street	string	lessee street
        values.lessee.zipCode	string	lessee zip code
        values.lessee.manager	Object	lessee's manager data
        values.lessee.manager.birthDate	string	lessee's manager birth date (format required: "YYYY-MM-DD")
        values.lessee.manager.city	string	lessee's manager city
        [values.lessee.manager.faxNumber]	string	lessee's manager phone number (optional)
        values.lessee.manager.firstName	string	lessee's manager first name
        values.lessee.manager.lastName	string	lessee's manager last name
        [values.lessee.manager.phoneNumber]	string	lessee's manager phone number (optional)
        values.lessee.manager.salutation	number	lessee's manager salutation form (result of getSalutations() method)
        values.lessee.manager.street	string	lessee's manager street
        values.lessee.manager.zipCode	string	lessee's manager zip code
        values.leaseTerm	number	lease term (returned from getRates() method)
        values.object	string	name of the object (80 char max)
        values.paymentMethod	number	payment method (result of getPaymentMethods() method)
        values.productGroup	number	product group (is a part of "credentials". Can be assigned by Albis only)
        [values.promotionId]	string	lease term (returned from getRates() if conditions matched any promotion) (optional)
        values.purchasePrice	number	purchase price (object value)
        values.rate	number	rate (returned from getRates() method)
        [values.reference]	string	application reference (helper for shop employees) (optional)
        [values.receiverEndpoint]	string	endpoint address where requests about application/documentation updates should be delivered (optional)
        [values.receiverFailEmails]	Array.<String>	array of string emails where info about connection with reveiver endpoint should be delivered (optional)
        [values.receiverToken]	string	a string, which can be used by a client to ensure that the notification concerns his application (optional)
        [values.residualValuePercent]	number	required if contract type equals 2 (optional)
        [values.serviceFee]	number	required if contract type equals 7 or 12 (optional)
    */
    function saveFrameSubApplication($values,$returnType = false){
        if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('frame-sub-applications',json_encode(Albis::utf8ize($values)),$token, false, "POST"),$returnType);
    }

    /** sets application status to canceled
    *   @param [$applicationId] id of application to cancel
    *   @param [$cancelationReason] id of cancellation reason. Can be left empty
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function deleteApplication($applicationId,$cancelationReason = false, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        $parameterArray = array("applicationId"=>$applicationId);
        if($cancelationReason !== false)$parameterArray['cancelationReason'] = $cancelationReason;
        return Albis::formatJsonReturn($this->sendPost('application',$parameterArray,$token, false, "DELETE"),$returnType);
    }

    /** returns payment method definitions
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getPaymentMethods($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('payment-methods',[],$token, false, "GET"),$returnType);
    }

    /** returns contract type definitions
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getContractTypes($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('contract-types',[],$token, false, "GET"),$returnType);
    }

    function setApplicationObjectStandardValues(&$applicationObject){
        if($this->config->GET_STANDARD_APPLICATION_VALUES() == null){
            return;
        }
        if(!is_array($this->config->GET_STANDARD_APPLICATION_VALUES())){
            return;
        }
        if(is_array($applicationObject)){
            foreach($this->config->GET_STANDARD_APPLICATION_VALUES() as $key => $value){
                if(!isset($applicationObject[$key])){
                     $applicationObject[$key] = $value;
                }
            }
        }elseif(is_object($applicationObject)){
            foreach($this->config->GET_STANDARD_APPLICATION_VALUES() as $key => $value){
                if(!isset($applicationObject->$key)){
                     $applicationObject->$key = $value;
                }
            }
        }
    }

    /** returns legal form definitions
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getLegalForms($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('legal-forms',[],$token, false, "GET"),$returnType);
    }

    /** get rates from Albis via associative array (variant of gerRates)
    *   @param $assoc associative array containing the following fields
    *       "contractType" the type-id (integer) of the contract
    *      "$downPayment" amount of down payment (decimal value)
    *       "object" the object name (string)
    *       "paymentMethod" id of payment method
    *       "productGroup" id of product group
    *       "purchasePrice" amount of purchase price
    *       "provision" provision type id
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getRatesByAssoc($assoc, $returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('rate',$assoc,$token, false, "GET"),$returnType);
    }

    /** get rates from Albis
    *   @param $contractType the type-id (integer) of the contract
    *   @param $downPayment amount of down payment (decimal value)
    *   @param $object the object name (string)
    *   @param $paymentMethod id of payment method
    *   @param $productGroup id of product group
    *   @param $purchasePrice amount of purchase price
    *   @param $provision provision type id
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getRates($contractType,$downPayment,$object,$paymentMethod,$productGroup,$purchasePrice,$provision,$returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $valueArray = array('contractType' =>$contractType,
                            'downPayment' =>$downPayment,
                            'object' =>$object,
                            'paymentMethod' =>$paymentMethod,
                            'productGroup' =>$productGroup,
                            'purchasePrice' =>$purchasePrice,
                            'provision' =>$provision
                        );
        return $this->getRatesByAssoc($valueArray,$returnType);
    }
    
    //TODO: documentation
    function getFrameRates($applicationId, $purchasePrice, $productGroup, $downPayment, $contractType, $paymentMethod,$returnType = false){
        if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $valueArray = array('applicationId' => $applicationId,
                            'purchasePrice' =>$purchasePrice,
                            'productGroup' =>$productGroup,
                            'downPayment' =>$downPayment,
                            'contractType' =>$contractType,
                            'paymentMethod' =>$paymentMethod
                        );
        return $this->getFrameRatesByAssoc($valueArray,$returnType);
        
    }
    
    //TODO: documentation
    function getFrameRatesByAssoc($assoc,$returnType = false){
        if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('frame-rates',$assoc,$token, false, "GET"),$returnType);
    }

    /** returns salutation definitions
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getSalutations($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('salutations',[],$token, false, "GET"),$returnType);
    }

    /** returns product group definitions
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    *   @return response from Albis in requested return type
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getProductGroups($returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
        $token = $this->getAlbisToken();
        return Albis::formatJsonReturn($this->sendPost('product-groups',[],$token, false, "GET"),$returnType);
    }

    /** returns document (PDF) as base64 string (variant of getContractDocuments)
    *   @param $assoc associative array with the following fields:
            "applicationId" => Albis application id
    *       "purchasePrice" => the requested purchase price
    *       "iban" => IBAN to be referenced by the document
    *       "rate" => payment rate
    *   @return PDF as base64 string
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getContractDocumentsByAssoc($assoc){
        $token = $this->getAlbisToken();
        $jso = $this->sendPost('contract-documents',$assoc,$token, false, "GET");
        $ret = json_decode($jso);
        return $ret->result;
    }

    /** returns document (PDF) as base64 string.
    *   @param $applicationId Albis application id
    *   @param $purchasePrice the requested purchase price
    *   @param $iban IBAN to be referenced by the document
    *   @param $rate payment rate
    *   @return PDF as base64 string
    *   @throws Exception if endpoint declines request or problems in token aquisition
    */
    function getContractDocuments($applicationId,$purchasePrice,$iban,$rate){
         $valueArray = array('applicationId' =>$applicationId,
                            'purchasePrice' =>$purchasePrice,
                            'iban' =>$iban,
                            'rate' =>$rate
                        );
        return $this->getContractDocumentsByAssoc($valueArray);
    }

    /** streams base64 String as pdf to the client; exits after finished unless optional parameter is given
    *   @param $base64 base64 string of the file to stream
    *   @param [$close] exit after streaming
    *   @return void
    */
    function streamDocuments($base64, $close = true){
        header('Content-Description: File Transfer');
        header("Content-type: application/octet-stream");
        header("Content-disposition: attachment; filename=document.pdf");
        echo base64_decode($bas64);
        if($close)exit();
    }

    /** uploads documents to an existing application
    *   @param $applicationId Albis application id
    *   @param $documentArray array of document objects or associative arrays
    *   @param {number} $documentArray[].art - document type number (possible values: 1 for Identity card, 2 for Acquired possession form, 3 for Signed contract, 4 for Direct debit authorization, 99 for miscellaneous)
    *   @param {string} $documentArray[].ext - file extension (possible values: 'pdf', 'jpg', 'jpeg', 'png')
    *   @param {string} $documentArray[].doc - string created by file encoding using base64
    *   @param [$returnType] requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    */
    function uploadContractDocuments($applicationId,$documentArray,$returnType = false){
		if($returnType === false)$returnType = $this->config->GET_RETURN_TYPE_STANDARD();
          if(!is_array($documentArray)){
              $documentArray = [$documentArray];
          }
          $assoc = array('id' => $applicationId,
                        'documents' => $documentArray);
          return Albis::formatJsonReturn($this->sendPost('contract-documents',$assoc,$token),$returnType);
    }

    //----------------------------------------------------------------
    //----------------- static utility classes -----------------------
    //----------------------------------------------------------------
    /** returns value from given key from storage.
    *   php-native session handling is taken in standard
    *   @param $key the key of the key-value-pair
    *   @return the value in storage, null if no such key is set
    */
    static function getStorage($key){
        if(!isset($_SESSION[$key])){ //technically not necessary, here to insert exception handling if needed
            return null;
        }
        return $_SESSION[$key];
    }

    /** sets value for given key in storage.
    *   php-native session handling is taken in standard
    *   @param $key the key of the key-value-pair
    *   @param $value the value to set
    *   @return void
    */
    static function setStorage($key,$value){
        $_SESSION[$key] = $value;
    }

    /** removes key-value-pair with given key from storage.
    *   php-native session handling is taken in standard
    *   @param $key the key of the key-value-pair
    *   @return void
    */
    static function killStorage($key){
        unset($_SESSION[$key]);
    }

    /** transfers / formats a given JSON-String into either a raw text,
    *   an associative array or a php-object
    *   @param $json the json string to be formatted
    *   @param $returnType requested return type (AbasConfig->RETURN_TYPE_RAW,AbasConfig->RETURN_TYPE_OBJECT,AbasConfig->RETURN_TYPE_ASSOC)
    */
    function formatJsonReturn($json,$returnType){
        if($returnType == $this->config->GET_RETURN_TYPE_OBJECT()){
            $ret = json_decode($json);
            if(isset($ret->result)){
                $ret = $ret->result;
            }
            return $ret;
        }
        if($returnType == $this->config->GET_RETURN_TYPE_ASSOC()){
            $ret = json_decode($json,true);
            if(isset($ret['result'])){
                $ret = $ret['result'];
            }
            return $ret;
        }
        return $json;
    }

    /** takes the request body and tries to interpret it as JSON.
    *   returns associative array of JSON on success
    */
    static function getRequestBodyJSONArray(){
        $requestBody = file_get_contents('php://input');
        $ret = json_decode($requestBody,true);
        return $ret;
    }

    /** creates an associative array to be used in the SDK for uploading documents
    *   @param $fileType type id of document type - either AbasConfig->DOCUMENT_TYPE_IDENTITY_CARD,
    *       DOCUMENT_TYPE_ACQUIRED_POSSESSION_FORM,DOCUMENT_TYPE_SIGNED_CONTRACT,
    *       DOCUMENT_TYPE_DEBIT_AUTHORIZATION or DOCUMENT_TYPE_MISC
    *   @param $fileExtension the File Extension
    *   @param $data the file's data, either as byte array or as base64 string
    *   @return associative array
    */
    static function createDocumentObjectArray($fileType,$fileExtension,$data){
        $base64 = null;
        if(is_array($data)){
            $byteString = "";
            foreach($data as $byte){
                $byteString .= pack('C',$byte);
            }
            $base64 = base64_encode($byteString);
        }else{
            $base64 = $data;
        }
        $ret = array('art' => $fileType,
                     'ext' => $fileExtension,
                     'doc' => $base64);
        return $ret;
    }

    /** creates an associative array to be used in the SDK for uploading documents
    *   @param $fileType type id of document type - either AbasConfig->DOCUMENT_TYPE_IDENTITY_CARD,
    *       DOCUMENT_TYPE_ACQUIRED_POSSESSION_FORM,DOCUMENT_TYPE_SIGNED_CONTRACT,
    *       DOCUMENT_TYPE_DEBIT_AUTHORIZATION or DOCUMENT_TYPE_MISC
    *   @param $fileExtension the File Extension
    *   @param $filename name of a file on the php server to be included in the array as a base64 encoded string
    *   @return associative array
    *   @throws Exception if file not found or unreadable
    */
    static function createDocumentObjectArrayByFile($fileType,$fileExtension,$filename){
        if(!is_file($filename))Albis::error("file not found or not a file; please check existence of file and file permissions: " . $filename,3,true);
        return Albis::createDocumentObjectArray($fileType,$fileExtension,base64_encode(file_get_contents($filename)));
    }
    
    static function utf8ize($d) {
        if (is_array($d)) {
            foreach ($d as $k => $v) {
                $d[$k] = Albis::utf8ize($v);
            }
        } else if (is_string ($d)) {
            return utf8_encode($d);
        }
        return $d;
    }

    /** basic exception wrapper class.
    *   override / change this for custom exception logging
    *   @param  $text the error text
    *   @param  $severity severity on a scale from 1-4 debug,log,warning,error
    *   @param  $throw if true, throws an exception
    *   @throws Exception if $throw is true
    */
    static function error($text,$severity,$throw){
        $message = "Error severity " . $severity . ":<br />" . $text;
        if($throw){
            throw new \Exception($message);
        }else{
            error_log($message);
        }
    }

    /** returns the endpoint of the Albis server, with api-stage and sub-call attached
    *   tests identity and validity of endpoint beforehand
    *   @param call the API-Call to attach
    *   @return string of complete endpoint
    *   @throws Exception if version is not "staging" nor a numeric value identical to the SDK version
    */
    function getEndpoint($call){
        $this->checkVersion($this->config->GET_API_STAGE());
        return $this->config->GET_ENDPOINT() . '/' . $this->config->GET_API_STAGE() . '/' . $call;
    }

    /** tests identity and validity of SDK version
    *   @return void
    *   @throws Exception if version is not "staging" nor a numeric value identical to the SDK version
    */
    function checkVersion($version){
       // if(1 !== preg_match('/^v[0-9]+$|^staging$/',$version)){
       //Regex unneccessarily slow; doing it by hand
        $vld = $version == 'staging';
        if(!$vld){
            $charArray = str_split($version);
            $len = sizeof($charArray);
            if($len > 1 && $charArray[0] == 'v'){
                $vld = true;
                for($i = 1; $i < $len; ++$i){
                    if(!is_numeric($charArray[$i])){
                        $vld = false;
                        break;
                    }
                }
            }
        }
        if(!$vld){
            Albis::error('invalid API-Version: ' . $version,2,true);
        }
        if(!($version == $this->config->GET_SDK_VERSION() || $version == 'staging')){
            Albis::error('Package version does not match API version',2,true);
        }
    }

    /** sends network request to albis server and returns the response
    *   @param $call the api call
    *   @param $contentToSend content to sent in either the body or as GET-call in URI (depending on method=
    *   @param [$authToken] Albis authentication token to attach
    *   @param [$isJson] set to true if $contentToSend is an object or associative array to be sent as JSON-String
    *   @param [$method] method to use (POST, GET, PUT,...)
    *   @return response body as string
    *   @throws exception in case of problem in sending or receiving (return code != 200).
       */
    function sendPost($call,$contentToSend,$authToken = false,$isJson = true, $method="POST"){
        // Create the context for the request
        $content = "";$header = [];
        if($isJson){
            if(is_array($contentToSend)){
                $content = json_encode($contentToSend);
            }else{
                $content = $contentToSend;
            }
            array_push($header,"Content-Type: application/json");
        }else{
            if(is_array($contentToSend)){
                $content = http_build_query($contentToSend);
            }else{
                $content = $contentToSend;
            }
            array_push($header,"Content-Type: application/x-www-form-urlencoded");
        }
        if($authToken !== false){
            array_push($header,"Authorization: Bearer ".$authToken);
        }
        $headerString = implode(PHP_EOL,$header);

        $url = $this->getEndpoint($call);
        if(($method == "GET" || $method == "DELETE") && !$isJson){
            $url .= "?" . $content;
        }
        if($this->config->GET_DEBUG_REQUESTS()){
            echo 'sending request to ' . $url . "\nwith method " . $method;
            echo "\nHeader:" . $headerString . "\n and content:";
            var_dump($content);
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        $method = strtoupper($method);
        if($method == "PUT"){
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            curl_setopt($ch, CURLOPT_POSTFIELDS,$content);
        }elseif($method == "GET"){
            curl_setopt($ch, CURLOPT_HTTPGET, 1);
        }elseif($method == "POST"){
             curl_setopt($ch, CURLOPT_POST, 1);
             curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER,$header);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        $returnCode =  curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($returnCode != 200){
            $err = $response;
            if(isset($err) && $err != ""){
                $err_obj = json_decode($response);
                $err_obj->returnCode = $returnCode;
                $err = json_encode($err_obj);
            }
            throw new \Exception($err);
        }
        curl_close ($ch);
        return $response;          
    }
}
 ?>
