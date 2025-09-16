<?php
/**
 * Test script for delegation validation
 */

// Load WordPress and plugin
require_once '../../../wp-config.php';
require_once 'vendor/autoload.php';
require_once 'includes/class-delegation-manager.php';
require_once 'includes/class-identity.php';

// Test data from the AJAX request
$test_delegation = [
    "delegation",
    "3915588b917d5524b96a309c92752e2e5a901d38c4b6a11bce45d1e7607de9156cb9c15f13dac51c8e2cf42853a6d11e1677c5b98e760b9211aac63bf81e12f7",
    "created_at>1758038669&created_at<1785814669&kind=31923",
    "54a340072ccc625516c8d572b638a828c5b857074511302fb4392f26e34e1913"
];

echo "=== Delegation Validation Test ===\n";

// Check if kornrunner library is available
echo "kornrunner\\Secp256k1 exists: " . (class_exists('kornrunner\\Secp256k1') ? 'YES' : 'NO') . "\n";
echo "kornrunner\\Secp256k1\\Secp256k1 exists: " . (class_exists('kornrunner\\Secp256k1\\Secp256k1') ? 'YES' : 'NO') . "\n";

// Create delegation manager
$delegation_manager = new NostrCalendarDelegationManager();

// Create test event
$test_event = [
    'kind' => 31923,
    'created_at' => time(),
    'content' => 'test event',
    'tags' => [],
    'pubkey' => 'test_delegatee_pubkey_here'
];

// Test validation using reflection to access private method
$reflection = new ReflectionClass($delegation_manager);
$method = $reflection->getMethod('validate_delegation_signature');
$method->setAccessible(true);

try {
    $result = $method->invoke(
        $delegation_manager,
        $test_event,
        $test_delegation[3], // delegator_pubkey
        $test_delegation[2], // conditions  
        $test_delegation[1]  // signature
    );
    
    echo "\nValidation Result:\n";
    print_r($result);
    
} catch (Exception $e) {
    echo "\nValidation Error: " . $e->getMessage() . "\n";
}

echo "\n=== Test Complete ===\n";