<?php 
$ENDPOINT = '';
$API_STAGE = 'staging';
/** use cURL package for requests. This needs curl to be installed in your php environment, but allows for more fine-grained error-handling*/
$USE_CURL = true;

/** set this if you want to automatically set 
certain standard values on new or updated applications. Set as 
Associative Array of Values 
Example: 
$STANDARD_APPLICATION_VALUES = array('receiverEndpoint' => 'http://my-endpoint.url' );
would automatically set the callback.
*/
$STANDARD_APPLICATION_VALUES = null;


 ?>