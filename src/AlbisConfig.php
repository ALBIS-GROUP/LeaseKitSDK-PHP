<?php 
namespace Albis\Sdk;

class AlbisConfig{
    //--- constants ---
    /** Version of this sdk*/
    private $SDK_VERSION = "v1";
    /** integer constant to return albis requests as raw text */
    private $RETURN_TYPE_RAW=0;
    /** integer constant to return albis requests as php object */
    private $RETURN_TYPE_OBJECT=1;
    /** integer constant to return albis requests as associative array */
    private $RETURN_TYPE_ASSOC=2;
    /** integer constant for the Albis document type "Identity card" */    
    private $DOCUMENT_TYPE_IDENTITY_CARD=1;
    /** integer constant for the Albis document type "posession form" */
    private $DOCUMENT_TYPE_ACQUIRED_POSSESSION_FORM=2;
    /** integer constant for the Albis document type "signed contract" */
    private $DOCUMENT_TYPE_SIGNED_CONTRACT=3;
    /** integer constant for the Albis document type "debit authorization" */
    private $DOCUMENT_TYPE_DEBIT_AUTHORIZATION=4;
    /** integer constant for the Albis document type "miscellaneous" */
    private $DOCUMENT_TYPE_MISC=99;
    
    //--- basic configuration ---
    private $ENDPOINT;
    private $API_STAGE;
    
    //--- advanced configuration ---
    /** period before token expire date when a new token shall be requested, in seconds */
    private $TOKEN_EXPIRY_GRACE_PERIOD=3600;
    /** set to true to echo information regarding sent requests */
    private $DEBUG_REQUESTS = false;
    /** definition of standard return type for requests.
    Changing this might have unintented consequences in productive environments! */
    private $RETURN_TYPE_STANDARD=0;
    /** set this if you want to automatically set
    certain standard values on new or updated applications. Set as
    Associative Array of Values
    Example:
    $STANDARD_APPLICATION_VALUES = array('receiverEndpoint' => 'http://my-endpoint.url' );
    would automatically set the callback.
    */
    private $STANDARD_APPLICATION_VALUES = null;
 
    function __construct($endpoint, $apiStage){
        $this->ENDPOINT = $endpoint;
        $this->API_STAGE = $apiStage;
    }
    
    //--- Getter / Setter ---
    public function GET_SDK_VERSION(){
		return $this->SDK_VERSION;
	}

	public function GET_RETURN_TYPE_RAW(){
		return $this->RETURN_TYPE_RAW;
	}

	public function GET_RETURN_TYPE_OBJECT(){
		return $this->RETURN_TYPE_OBJECT;
	}

	public function GET_RETURN_TYPE_ASSOC(){
		return $this->RETURN_TYPE_ASSOC;
	}

	public function GET_DOCUMENT_TYPE_IDENTITY_CARD(){
		return $this->DOCUMENT_TYPE_IDENTITY_CARD;
	}

	public function GET_DOCUMENT_TYPE_ACQUIRED_POSSESSION_FORM(){
		return $this->DOCUMENT_TYPE_ACQUIRED_POSSESSION_FORM;
	}

	public function GET_DOCUMENT_TYPE_SIGNED_CONTRACT(){
		return $this->DOCUMENT_TYPE_SIGNED_CONTRACT;
	}

	public function GET_DOCUMENT_TYPE_DEBIT_AUTHORIZATION(){
		return $this->DOCUMENT_TYPE_DEBIT_AUTHORIZATION;
	}

	public function GET_DOCUMENT_TYPE_MISC(){
		return $this->DOCUMENT_TYPE_MISC;
	}

	public function GET_ENDPOINT(){
		return $this->ENDPOINT;
	}

	public function SET_ENDPOINT($ENDPOINT){
		$this->ENDPOINT = $ENDPOINT;
	}

	public function GET_API_STAGE(){
		return $this->API_STAGE;
	}

	public function SET_API_STAGE($API_STAGE){
		$this->API_STAGE = $API_STAGE;
	}

	public function GET_TOKEN_EXPIRY_GRACE_PERIOD(){
		return $this->TOKEN_EXPIRY_GRACE_PERIOD;
	}

	public function SET_TOKEN_EXPIRY_GRACE_PERIOD($TOKEN_EXPIRY_GRACE_PERIOD){
		$this->TOKEN_EXPIRY_GRACE_PERIOD = $TOKEN_EXPIRY_GRACE_PERIOD;
	}

	public function GET_DEBUG_REQUESTS(){
		return $this->DEBUG_REQUESTS;
	}

	public function SET_DEBUG_REQUESTS($DEBUG_REQUESTS){
		$this->DEBUG_REQUESTS = $DEBUG_REQUESTS;
	}

	public function GET_RETURN_TYPE_STANDARD(){
		return $this->RETURN_TYPE_STANDARD;
	}

	public function SET_RETURN_TYPE_STANDARD($RETURN_TYPE_STANDARD){
		$this->RETURN_TYPE_STANDARD = $RETURN_TYPE_STANDARD;
	}

	public function GET_STANDARD_APPLICATION_VALUES(){
		return $this->STANDARD_APPLICATION_VALUES;
	}

	public function SET_STANDARD_APPLICATION_VALUES($STANDARD_APPLICATION_VALUES){
		$this->STANDARD_APPLICATION_VALUES = $STANDARD_APPLICATION_VALUES;
	}
}

 ?>