<?php

/**
 * @file
 * Plugin definition for a key provider using Townsend Security’s Alliance Kay 
 * Manager service.
 */

$plugin = array(
  'title' => t('Townsend Security AKM'),
  'description' => t('Use Townsend Security’s Alliance Key Manager service for the encryption key.'),
  'key callback' => 'townsec_encrypt_akm_get_key',
  'settings form' => 'townsec_encrypt_akm_key_settings_form',
);

/**
 * Callback method to return the encryption key from the AKM service.
 */
function townsec_encrypt_akm_get_key($settings) {

  $server = $settings['akm_host_server'];
  $retrieve = $settings['akm_retrieve_port'];
  $encrypt = $settings['akm_encrypt_port'];
  $keytype = $settings['key_type'];
  $keyname = $settings['key_name'];
  $keysize = $settings['key_size'];
  $errno = NULL;
  $errstr = NULL;
  $encode = $settings['encode'];
  $local = drupal_get_path('module', 'townsend_akm') . '/' . $settings['client_cert_and_key_file'];
  $ca = drupal_get_path('module', 'townsend_akm') . '/' . $settings['ca_cert_file'];

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
  $opts = stream_context_get_options($ctx);
  $server_cert = $opts['ssl']['peer_certificate'];
  
  //Request Key
  if($fp){
    $request = sprintf("000712001%-40s%24s".$encode, $keyname, '');
    fputs($fp, $request);
    $len = fread($fp, 5);
    if($len){
      $rsp = fread($fp, $len + 1);
      if($rsp){
        $value = substr($rsp, 95);
      }
    }
    fclose($fp);
  } else{
    drupal_set_message($message = t('An error occurred'), 'error', TRUE);
  }

  return $value;
}

/**
 * Settings form for our key provider.
 */
function townsec_encrypt_akm_key_settings_form($defaults) {
  $form = array();

  $form['client_cert_and_key_file'] = array(
    '#type' => 'textfield',
    '#title' => t('Location of Client X509 Certificate and Private Key File'),
    '#description' => t('The file location may be absolute (e.g. %abs) or relative to the Drupal directory (e.g. %rel).', array(
      '%abs' => '/var/www',
      '%rel' => '../../keys',
    )),
    '#default_value' => isset($defaults['client_cert_and_key_file']) ? $defaults['client_cert_and_key_file'] : '',
    '#required' => TRUE,
  );
  $form['ca_cert_file'] = array(
    '#type' => 'textfield',
    '#title' => t('Location of Certificate Authority Certificate File'),
    '#description' => t('The file location may be absolute (e.g. %abs) or relative to the Drupal directory (e.g. %rel).', array(
      '%abs' => '/var/www',
      '%rel' => '../../keys',
    )),
    '#default_value' => isset($defaults['ca_cert_file']) ? $defaults['ca_cert_file'] : '',
    '#required' => TRUE,
  );
  $form['akm_host_server'] = array(
    '#type' => 'textfield',
    '#title' => t('AKM Host Server'),
    '#description' => t('Enter the AKM host server name or IP number.'),
    '#default_value' => isset($defaults['akm_host_server']) ? $defaults['akm_host_server'] : '',
    '#required' => TRUE,
  );
  $form['akm_retrieve_port'] = array(
    '#type' => 'textfield',
    '#title' => t('Key Retrieval Port'),
    '#description' => t('Enter the number of the port for key retrieval.'),
    '#default_value' => isset($defaults['akm_retrieve_port']) ? $defaults['akm_retrieve_port'] : '',
    '#required' => TRUE,
  );
  $form['akm_encrypt_port'] = array(
    '#type' => 'textfield',
    '#title' => t('Remote Encryption Port'),
    '#description' => t('Enter the number of the port for remote encryption.'),
    '#default_value' => isset($defaults['akm_encrypt_port']) ? $defaults['akm_encrypt_port'] : '',
    '#required' => TRUE,
  );
  $form['key_name'] = array(
    '#type' => 'textfield',
    '#title' => t('Key Name'),
    '#description' => t('Enter the name of the key.'),
    '#default_value' => isset($defaults['key_name']) ? $defaults['key_name'] : '',
    '#required' => TRUE,
  );
  $form['key_type'] = array(
    '#type' => 'select',
    '#title' => t('Key Type'),
    '#description' => t('Choose the type of key.'),
    '#options' => array(
      'AES-256' => t('AES-256'),
    ),
    '#default_value' => isset($defaults['key_type']) ? $defaults['key_type'] : 'AES-256',
  );
  $form['key_size'] = array(
    '#type' => 'textfield',
    '#title' => t('Key Size'),
    '#description' => t('Enter the size of the key.'),
    '#default_value' => isset($defaults['key_size']) ? $defaults['key_size'] : '',
    '#required' => TRUE,
  );
  $form['encode'] = array(
    '#type' => 'select',
    '#title' => t('Encoding Method'),
    '#description' => t('Choose the encoding method.'),
    '#options' => array(
      'BIN' => t('Binary'),
      'B64' => t('Base64 Encoded'),
      'B16' => t('Base16 Encoded'),
    ),
    '#default_value' => isset($defaults['key_type']) ? $defaults['encode'] : 'B64',
  );

  return $form;
}
