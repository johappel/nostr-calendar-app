<?php
/**
 * Nostr Calendar AJAX Handler
 * Handles AJAX requests from admin interface
 */

class NostrCalendarAjaxHandler {
    
    public function __construct() {
        $this->init_hooks();
    }
    
    public function init_hooks() {
        // AJAX handlers for admin
        add_action('wp_ajax_publish_nostr_event', [$this, 'handle_publish_event']);
        add_action('wp_ajax_get_calendar_identity', [$this, 'handle_get_identity']);
        add_action('wp_ajax_save_calendar_identity', [$this, 'handle_save_identity']);
    }
    
    /**
     * Handle publishing of already signed Nostr event
     */
    public function handle_publish_event() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'nostr_calendar_admin')) {
            wp_die('Security check failed');
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        // Get signed event from request
        $signed_event_json = sanitize_text_field($_POST['signed_event']);
        $signed_event = json_decode($signed_event_json, true);
        
        if (!$signed_event) {
            wp_send_json_error('Invalid event data');
            return;
        }
        
        error_log('[Nostr Calendar] Received signed event for publishing: ' . print_r($signed_event, true));
        
        // Initialize publisher
        global $nostr_calendar_publisher;
        if (!$nostr_calendar_publisher) {
            $nostr_calendar_publisher = new NostrCalendarPublisher();
        }
        
        // Publish the signed event
        $result = $nostr_calendar_publisher->publish_event($signed_event);
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * Handle getting calendar identity
     */
    public function handle_get_identity() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'nostr_calendar_admin')) {
            wp_die('Security check failed');
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        // Get identity from options
        $identity = get_option('nostr_calendar_identity');
        
        if ($identity) {
            wp_send_json_success($identity);
        } else {
            wp_send_json_success(null);
        }
    }
    
    /**
     * Handle saving calendar identity
     */
    public function handle_save_identity() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'nostr_calendar_admin')) {
            wp_die('Security check failed');
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        // Get identity from request
        $identity_json = sanitize_text_field($_POST['identity']);
        $identity = json_decode($identity_json, true);
        
        if (!$identity || !isset($identity['private_key']) || !isset($identity['pubkey'])) {
            wp_send_json_error('Invalid identity data');
            return;
        }
        
        // Validate identity format
        if (!preg_match('/^[0-9a-f]{64}$/i', $identity['private_key']) || 
            !preg_match('/^[0-9a-f]{64}$/i', $identity['pubkey'])) {
            wp_send_json_error('Invalid key format');
            return;
        }
        
        // Save identity
        $saved = update_option('nostr_calendar_identity', $identity);
        
        if ($saved) {
            error_log('[Nostr Calendar] Identity saved: pubkey=' . $identity['pubkey']);
            wp_send_json_success('Identity saved successfully');
        } else {
            wp_send_json_error('Failed to save identity');
        }
    }
}
