<?php


function townsend_akm_connect(){
  // Declare these up front but will get them from interface if available;
  $server = '216.211.138.178';
  $bkup = '216.211.138.178';
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
  $host = 'tls://'.$server.':'.$encrypt;
  $backup = 'tls://'.$bkup.':'.$encrypt;
  //Create actual connection to key server
  
/*
  $fp = stream_socket_client($host, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
  //var_dump($errno);
  //TESTING DUMP SERVER CERTS
  $opts = stream_context_get_options($ctx);
  $server_cert = $opts['ssl']['peer_certificate'];
*/
  //var_dump(openssl_x509_parse($server_cert));
  
  //Request Key
  if($fp = stream_socket_client($host, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx)){

/*
Key Length = 40 (left justify pad on right)
Instance = 24 (leave blank or instance got back)
*/

    $request = sprintf("000982019YNBIN00016YNYY1111111111111111TESTKEY                                                         aaaaaaaaaaaaaaaa");
    fputs($fp, $request);
    $len = fread($fp, 5);
    if($len){
      $return = fread($fp, $len + 16);
      if($return){
        $inst = substr($return, 15, 24);
        var_dump($inst);
        $coded = substr($return, 39);
        var_dump($coded);
      }
      }

    fclose($fp);
  }
  $iv = 1111111111111111;
  $key = 'TESTKEY                                 ';
  $fp = stream_socket_client($host, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
    
    $decrypt_header = "001012021YNBIN00016BINYNYY".$iv."".$key."".$inst."";
    $decrypt = sprintf("".$decrypt_header."".$coded."");
    var_dump($decrypt_header);
    var_dump($inst);
    var_dump($key);
    var_dump($iv);
    var_dump($decrypt);
    fputs($fp, $decrypt);    
    $len = fread($fp, 5);
    if($len){
      $rsp = fread($fp, $len + 16);
      if($rsp){
        var_dump($rsp);
      }
    }
    fclose($fp);
  
}

function townsend_akm_errorHandler($errno, $errstr){
  echo"<br />\nerror [$errno] $errstr";
  return false;
}

