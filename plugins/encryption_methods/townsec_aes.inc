<?php

/**
 * @file
 * Plugin definition for the Townsend Security AES encryption method.
 */

$plugin = array(
  'title' => t('Townsend Security AES'),
  'description' => t('This encryption method uses the Townsend Security Alliance Key Manager onboard AES encryption to provide remote NIST certified encryption of sensitive data.'),
  'encrypt callback' => 'townsec_encrypt_encryption_method_aes',
);

/**
 * Callback for Encrypt implementation: default
 *
 * This method uses a simple encryption method of character
 * replacement.
 */
function townsec_encrypt_encryption_method_aes($op = 'encrypt', $text = '', $key = '', $options = array()) {
  $processed_text = '';

  // Caching length operations to speed up for loops.
  $text_length = strlen($text);
  $key_length = strlen($key);

  // Loop through each character.
  for ($i = 0; $i < $text_length; $i++) {
    $char = substr($text, $i, 1);
    $keychar = substr($key, ($i % $key_length) - 1, 1);
    // Encrypt or decrypt the character.
    if ($op == 'decrypt') {
      $char = chr(ord($char) - ord($keychar));
    }
    else {
      $char = chr(ord($char) + ord($keychar));
    }
    $processed_text .= $char;
  }

  return $processed_text;
}
