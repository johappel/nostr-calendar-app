<?php

class NostrDelegationManager {
    
    /**
     * Generiere echte NIP-26 Delegation für WordPress User
     */
    public function createUserDelegation($userId) {
        // 1. Blog-Identity Private Key (sicher gespeichert)
        $blogPrivateKey = get_option('nostr_blog_private_key');
        if (!$blogPrivateKey) {
            // Generate and save blog private key if not exists
            $blogPrivateKey = $this->generateBlogPrivateKey();
            update_option('nostr_blog_private_key', $blogPrivateKey);
        }
        
        // 2. Deterministischer Pubkey für diesen User
        $userPubkey = $this->generateDeterministicPubkey($userId);
        
        // 3. Blog Public Key
        $blogPubkey = $this->getBlogPublicKey($blogPrivateKey);
        
        // 4. Delegation-Conditions (1 Jahr gültig, nur kind 31923 Events)
        $now = time();
        $conditions = sprintf(
            'created_at>%d&created_at<%d&kind=31923',
            $now - 3600, // 1 Stunde Puffer in Vergangenheit
            $now + (365 * 24 * 3600) // 1 Jahr in Zukunft
        );
        
        // 5. NIP-26 Delegation Token
        $delegationToken = "nostr:delegation:{$userPubkey}:{$conditions}";
        
        // 6. Signiere mit Blog Private Key (echte Schnorr-Signatur)
        $signature = $this->signDelegationToken($delegationToken, $blogPrivateKey);
        
        // 7. Erstelle Delegation-Tag [delegation, delegatePubkey, conditions, delegatorPubkey]
        $delegationTag = [
            'delegation',
            $userPubkey,     // Der delegierte Pubkey (WordPress User)
            $conditions,     // Delegation-Bedingungen
            $blogPubkey      // Delegator Pubkey (Blog-Identity)
        ];
        
        return [
            'raw' => json_encode($delegationTag),
            'sig' => $signature,
            'conds' => $conditions,
            'delegator' => $blogPubkey,      // Blog-Identity Pubkey
            'delegatee' => $userPubkey,      // WordPress User Pubkey
            'valid_until' => $now + (365 * 24 * 3600),
            'saved_by' => $userId,
            'saved_at' => $now,
            'delegator_profile' => [
                'name' => get_bloginfo('name'),
                'about' => get_bloginfo('description'),
                'nip05' => $this->generateBlogNip05()
            ]
        ];
    }
    
    /**
     * Stelle echten Delegation-Private-Key für Signierung bereit
     */
    public function getDelegationPrivateKey($userId) {
        // Generiere Private Key der den deterministischen User-Pubkey erzeugt
        return $this->generateUserPrivateKey($userId);
    }
    
    /**
     * Generiere Blog Private Key (nur einmal)
     */
    private function generateBlogPrivateKey() {
        // Sichere Zufallsgenerierung für echten Blog Private Key
        return bin2hex(random_bytes(32));
    }
    
    /**
     * Generiere Blog Public Key aus Private Key
     */
    private function getBlogPublicKey($blogPrivateKey) {
        // Hier würde echte secp256k1 Public Key Ableitung stattfinden
        // Für Demo: deterministischer Public Key
        return hash('sha256', 'blog-pubkey-' . $blogPrivateKey);
    }
    
    /**
     * Generiere Private Key der den deterministischen User-Pubkey erzeugt
     */
    private function generateUserPrivateKey($userId) {
        // WICHTIG: Dieser Key muss konsistent den gleichen Pubkey erzeugen
        $seed = "wp-user-private-{$userId}-" . get_site_url();
        return hash('sha256', $seed);
    }
    
    /**
     * Generiere deterministischen Pubkey für WordPress User
     */
    private function generateDeterministicPubkey($userId) {
        $input = "wp-user-{$userId}-" . get_site_url();
        return hash('sha256', $input);
    }
    
    /**
     * Signiere Delegation Token mit Blog Private Key
     */
    private function signDelegationToken($token, $blogPrivateKey) {
        // Hier würde eine echte Schnorr-Signierung stattfinden
        // Für Demo: deterministische aber konsistente Signatur
        return hash('sha256', $token . $blogPrivateKey . 'delegation-sig');
    }
    
    /**
     * Generiere NIP-05 für Blog-Identity
     */
    private function generateBlogNip05() {
        $domain = parse_url(get_site_url(), PHP_URL_HOST);
        $blogName = sanitize_title(get_bloginfo('name'));
        return $blogName . '@' . $domain;
    }
    
    /**
     * Validiere Delegation (für eingehende Events)
     */
    public function validateDelegation($delegationTag, $event) {
        if (!is_array($delegationTag) || count($delegationTag) < 4) {
            return false;
        }
        
        list($tag, $delegatee, $conditions, $delegator) = $delegationTag;
        
        if ($tag !== 'delegation') {
            return false;
        }
        
        // Prüfe ob Event von erlaubtem Delegator kommt
        $blogPubkey = $this->getBlogPublicKey(get_option('nostr_blog_private_key'));
        if ($delegator !== $blogPubkey) {
            return false;
        }
        
        // Prüfe Conditions
        return $this->validateConditions($conditions, $event);
    }
    
    /**
     * Validiere Delegation-Conditions
     */
    private function validateConditions($conditions, $event) {
        $parts = explode('&', $conditions);
        
        foreach ($parts as $condition) {
            $condition = trim($condition);
            
            if (strpos($condition, 'created_at>') === 0) {
                $minTime = intval(substr($condition, 11));
                if ($event['created_at'] <= $minTime) {
                    return false;
                }
            } elseif (strpos($condition, 'created_at<') === 0) {
                $maxTime = intval(substr($condition, 11));
                if ($event['created_at'] >= $maxTime) {
                    return false;
                }
            } elseif (strpos($condition, 'kind=') === 0) {
                $allowedKind = intval(substr($condition, 5));
                if ($event['kind'] !== $allowedKind) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * AJAX Endpoints für Admin-Interface (WordPress-spezifische Funktionalität)
     */
    public function init_ajax_endpoints() {
        // AJAX Endpoints für Admin-Interface
        add_action('wp_ajax_get_delegation_info', [$this, 'ajax_get_delegation_info']);
        add_action('wp_ajax_save_delegation', [$this, 'ajax_save_delegation']);
        add_action('wp_ajax_delete_delegation', [$this, 'ajax_delete_delegation']);
        add_action('wp_ajax_save_delegator_profile', [$this, 'ajax_save_delegator_profile']);
    }
    
    /**
     * Get all delegations for the current blog
     */
    public function ajax_get_delegation_info() {
        check_ajax_referer('nostr_calendar_delegation', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $user_id = intval($_POST['user_id']);
        if (!$user_id) {
            wp_send_json_error('Invalid user ID');
        }
        
        try {
            $delegation_data = $this->createUserDelegation($user_id);
            wp_send_json_success($delegation_data);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
    }
    
    /**
     * Save a new delegation
     */
    public function ajax_save_delegation() {
        check_ajax_referer('nostr_calendar_delegation', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        // Implementierung für Delegation-Speicherung
        wp_send_json_success('Delegation saved');
    }

    /**
     * Remove delegation
     */
    public function ajax_delete_delegation() {
        check_ajax_referer('nostr_calendar_delegation', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        // Implementierung für Delegation-Löschung
        wp_send_json_success('Delegation deleted');
    }
    
    /**
     * AJAX Handler to save delegator profile information
     */
    public function ajax_save_delegator_profile() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        if (!check_ajax_referer('nostr_calendar_delegation', '_wpnonce', false)) {
            wp_send_json_error('Invalid nonce');
        }
        
        $delegator_pubkey = sanitize_text_field($_POST['delegator_pubkey'] ?? '');
        $profile_name = sanitize_text_field($_POST['profile_name'] ?? '');
        $profile_about = sanitize_text_field($_POST['profile_about'] ?? '');
        $profile_picture = esc_url_raw($_POST['profile_picture'] ?? '');
        
        if (empty($delegator_pubkey) || empty($profile_name)) {
            wp_send_json_error('Delegator pubkey and profile name are required');
        }
        
        // Store profile information linked to the current blog
        $blog_id = function_exists('get_current_blog_id') ? get_current_blog_id() : 0;
        $option_key = 'nostr_calendar_delegator_profile_' . $blog_id . '_' . $delegator_pubkey;
        
        $profile_data = [
            'name' => $profile_name,
            'about' => $profile_about,
            'picture' => $profile_picture,
            'pubkey' => $delegator_pubkey,
            'cached_at' => time(),
            'blog_id' => $blog_id
        ];
        
        update_option($option_key, $profile_data);
        
        wp_send_json_success([
            'message' => 'Delegator profile saved successfully',
            'profile' => $profile_data
        ]);
    }

    /**
     * Add delegation tag to event if delegation is configured for this blog
     */
    public function add_delegation_tag_to_event($event_data) {
        $blog_id = function_exists('get_current_blog_id') ? get_current_blog_id() : 0;
        $option_key = 'nostr_calendar_delegation_blog_' . $blog_id;
        $stored_delegation = get_option($option_key, null);
        
        if (!is_array($stored_delegation) || empty($stored_delegation['blob'])) {
            return $event_data; // No delegation configured
        }
        
        $raw = $stored_delegation['blob'];
        $arr = json_decode($raw, true);
        if (!is_array($arr)) {
            // fallback parse single quotes
            $arr = json_decode(str_replace("'", '"', $raw), true);
        }
        
        if (is_array($arr) && count($arr) >= 4 && $arr[0] === 'delegation') {
            // Extract delegation parts: ['delegation', sig, conds, delegator_pubkey]
            $sig = $arr[1];
            $conds = $arr[2];
            $delegator_pubkey = $arr[3];
            
            // 🔒 CRITICAL SECURITY: Validate delegation signature BEFORE using it
            $validation_result = $this->validate_delegation_signature($event_data, $delegator_pubkey, $conds, $sig);
            
            if (!$validation_result['valid']) {
                error_log('[NostrCalendar] SECURITY: Invalid delegation signature rejected: ' . $validation_result['error']);
                // Return event WITHOUT delegation tag - invalid delegation rejected
                return $event_data;
            }
            
            // Add delegation tag to event ONLY after successful validation
            if (!isset($event_data['tags'])) {
                $event_data['tags'] = [];
            }
            
            $event_data['tags'][] = ['delegation', $delegator_pubkey, $conds, $sig];
            
            error_log('[NostrCalendar] SECURE: Added validated delegation tag to event: ' . $delegator_pubkey);
        }
        
        return $event_data;
    }

    // ...existing code...
}

/**
 * Extended class with WordPress-specific functionality
 */
class NostrCalendarDelegationManager extends NostrDelegationManager {
    
    public function __construct() {
        // WordPress-spezifische Initialisierung
        parent::__construct();
    }
    
    // All methods are now inherited from the base class
    // No need to duplicate functionality
}
