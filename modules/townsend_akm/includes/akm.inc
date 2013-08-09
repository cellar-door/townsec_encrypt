<?php


function townsend_akm_connect(){
  // Declare these up front but will get them from interface if available;
  $server = '216.211.138.178';
  $retrieve = '6000';
  $encrypt = '6003';
  $keytype = 'AES-256';
  $keyname = 'TESTKEY';
  $keysize = 256;
  $errno = NULL;
  $errstr = NULL;
  $encode = "B64";
  $local = drupal_get_path('module', 'townsend_akm') . '/cert/local.pem';
  $ca = drupal_get_path('module', 'townsend_akm') . '/cert/ca.pem';
  
  //Create TLS Connection with provided key locations
  $opts = array(
    'ssl' => array(
      'cafile' => $ca,
      'capture_peer_cert' => true,
      'local_cert' => $local,
      'verify_peer' => true,
    )
  );
  
  //Create TLS context
  $ctx = stream_context_create($opts);
  //Set the Server location and port
  $host = 'tls://'.$server.':'.$retrieve;
  //Create actual connection to key server
  
  $fp = stream_socket_client($host, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
  var_dump($fp);
  //TESTING DUMP SERVER CERTS
  $opts = stream_context_get_options($ctx);
  $server_cert = $opts['ssl']['peer_certificate'];
  var_dump(openssl_x509_parse($server_cert));
  
  //Request Key
  if($fp){
    $request = sprintf("000712001%-40s%24s".$encode, $keyname, '');
    fputs($fp, $request);
    $len = fread($fp, 5);
    if($len){
      $rsp = fread($fp, $len + 1);
      if($rsp){
        $value = substr($rsp, 95);
        echo "<p>You connected successfully and retrieved the following key: <b> $value </b></p>";
      }
    }
    fclose($fp);
  } else{
    echo "<p>You connection was not correctly administered. Please check your credentials and try again. errno: $errno, errstr: $errstr</p>";
  }
  
}

function townsend_akm_errorHandler($errno, $errstr){
  echo"<br />\nerror [$errno] $errstr";
  return false;
}

