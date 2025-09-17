<?php
/**
 * REST API Handler for Nostr Calendar
 */

class NostrCalendarRestAPI {
    
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
    }
    
    public function register_routes() {
        register_rest_route('nostr-calendar/v1', '/me', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_get_user_info'),
            'permission_callback' => array($this, 'rest_permission_check')
        ));
        
        register_rest_route('nostr-calendar/v1', '/token', array(
            'methods' => 'POST',
            'callback' => array($this, 'rest_get_token'),
            'permission_callback' => array($this, 'rest_permission_check')
        ));
        
        register_rest_route('nostr-calendar/v1', '/debug', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_debug_auth'),
            'permission_callback' => '__return_true'
        ));
        
        // Event management endpoints
        register_rest_route('nostr-calendar/v1', '/events', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_get_events'),
            'permission_callback' => array($this, 'rest_permission_check')
        ));
        
        register_rest_route('nostr-calendar/v1', '/events', array(
            'methods' => 'POST',
            'callback' => array($this, 'rest_create_event'),
            'permission_callback' => array($this, 'rest_permission_check')
        ));
        
        // NEW: Delegation private key endpoint  
        register_rest_route('nostr-calendar/v1', '/delegation-private-key', [
            'methods' => 'GET',
            'callback' => [$this, 'get_delegation_private_key'],
            'permission_callback' => [$this, 'rest_permission_check'] // Use existing method
        ]);
    }
    
    public function rest_permission_check() {
        // Check for SSO token first (more reliable)
        $token = $this->get_request_token();
        
        if ($token) {
            $payload = $this->verify_token($token);
            if ($payload && $payload['wp_user_id']) {
                // Set current user temporarily for this request
                wp_set_current_user($payload['wp_user_id']);
                return true;
            }
        }
        
        // Fallback to regular WordPress authentication
        return is_user_logged_in();
    }
    
    /**
     * Helper function to get token from request
     */
    private function get_request_token() {
        // Check query parameter first (most reliable for WordPress)
        if (isset($_GET['sso_token'])) {
            return sanitize_text_field($_GET['sso_token']);
        }
        
        // Check POST data
        if (isset($_POST['sso_token'])) {
            return sanitize_text_field($_POST['sso_token']);
        }
        
        // Check Authorization header (multiple ways)
        $auth_header = null;
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        }
        
        // Fallback for nginx/other servers
        if (!$auth_header && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        
        // Another fallback
        if (!$auth_header && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        
        if ($auth_header && strpos($auth_header, 'Bearer ') === 0) {
            return substr($auth_header, 7);
        }
        
        return null;
    }
    
    /**
     * Verify SSO token
     */
    public function verify_token($token) {
        // Get shared secret from SSO manager
        global $nostr_calendar_sso_manager;
        if (!$nostr_calendar_sso_manager) {
            return false;
        }
        
        return $nostr_calendar_sso_manager->verify_token($token);
    }
    
    /**
     * REST API Endpoint: Benutzer-Informationen abrufen
     */
    public function rest_get_user_info($request) {
        $user_id = get_current_user_id();
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            return new WP_Error('user_not_found', 'Benutzer nicht gefunden', array('status' => 404));
        }
        
        // Prefer stored usermeta pubkey if present
        $meta_pub = get_user_meta($user_id, 'nostr_calendar_pubkey', true);
        
        // Use SSO manager to generate deterministic pubkey
        global $nostr_calendar_sso_manager;
        $pubkey = $meta_pub;
        if (!$pubkey && $nostr_calendar_sso_manager) {
            $pubkey = $nostr_calendar_sso_manager->generate_deterministic_pubkey($user_id);
        }
        if (!$pubkey) {
            // Fallback
            $input = 'wp-user-' . $user_id . '-' . site_url();
            $pubkey = hash('sha256', $input);
        }

        // Check if a delegation is stored for this blog and include it in the response
        $blog_id = function_exists('get_current_blog_id') ? get_current_blog_id() : 0;
        $option_key = 'nostr_calendar_delegation_blog_' . $blog_id;
        $stored_delegation = get_option($option_key, null);
        $delegation = null;
        if (is_array($stored_delegation) && !empty($stored_delegation['blob'])) {
            $raw = $stored_delegation['blob'];
            $arr = json_decode($raw, true);
            if (!is_array($arr)) {
                // fallback parse single quotes
                $arr = json_decode(str_replace("'", '"', $raw), true);
            }
            if (is_array($arr) && count($arr) >= 4 && $arr[0] === 'delegation') {
                $delegation = array(
                    'raw' => $raw,
                    'sig' => $arr[1],
                    'conds' => $arr[2],
                    'delegator' => $arr[3],
                    'saved_by' => $stored_delegation['saved_by'] ?? null,
                    'saved_at' => $stored_delegation['saved_at'] ?? null
                );
                
                // Load cached delegator profile if available
                $delegator_pubkey = $delegation['delegator'];
                $profile_option_key = 'nostr_calendar_delegator_profile_' . $blog_id . '_' . $delegator_pubkey;
                $cached_profile = get_option($profile_option_key, null);
                
                if ($cached_profile && is_array($cached_profile)) {
                    $delegation['delegator_profile'] = [
                        'name' => $cached_profile['name'] ?? 'Unbekannt',
                        'about' => $cached_profile['about'] ?? '',
                        'picture' => $cached_profile['picture'] ?? '',
                        'cached_at' => $cached_profile['cached_at'] ?? null
                    ];
                }
                
                // If delegation exists, prefer delegator as calendar_identity.pubkey to show the authority who delegated
                $pubkey = $delegation['delegator'];
            }
        }
 
        $response = array(
            'success' => true,
            'user' => array(
                'id' => $user_id,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'display_name' => $user->display_name,
                'roles' => $user->roles
            ),
            'site_url' => site_url(),
            'calendar_identity' => array(
                'pubkey' => $pubkey,
                'name' => $user->display_name ?: $user->user_login,
                'about' => 'WordPress Benutzer von ' . site_url(),
                'nip05' => $user->user_login . '@' . parse_url(site_url(), PHP_URL_HOST)
            )
        );

        // If delegation exists and we have cached profile data, use delegator's name as calendar identity
        if ($delegation) {
            $response['calendar_identity']['delegation'] = $delegation;
            
            // Use delegator's profile name if available
            if (isset($delegation['delegator_profile']['name']) && !empty($delegation['delegator_profile']['name'])) {
                $response['calendar_identity']['name'] = $delegation['delegator_profile']['name'];
                $response['calendar_identity']['about'] = $delegation['delegator_profile']['about'] ?: 'Nostr Delegator';
                if (!empty($delegation['delegator_profile']['picture'])) {
                    $response['calendar_identity']['picture'] = $delegation['delegator_profile']['picture'];
                }
            }
        }

        return $response;
    }
    
    /**
     * REST API Endpoint: Token generieren
     */
    public function rest_get_token($request) {
        $user_id = get_current_user_id();
        
        global $nostr_calendar_sso_manager;
        if (!$nostr_calendar_sso_manager) {
            return new WP_Error('sso_not_available', 'SSO Manager nicht verfügbar', array('status' => 500));
        }
        
        $token = $nostr_calendar_sso_manager->generate_nostr_token($user_id);
        
        if ($token) {
            return array(
                'success' => true,
                'token' => $token
            );
        }
        
        return new WP_Error('token_failed', 'Token-Generierung fehlgeschlagen', array('status' => 500));
    }
    
    /**
     * REST API Endpoint: Debug authentication
     */
    public function rest_debug_auth($request) {
        return array(
            'authenticated' => is_user_logged_in(),
            'user_id' => get_current_user_id(),
            'token_present' => $this->get_request_token() !== null,
            'token_valid' => $this->get_request_token() ? (bool)$this->verify_token($this->get_request_token()) : false
        );
    }
    
    /**
     * REST API Endpoint: Events abrufen
     */
    public function rest_get_events($request) {
        // Simple implementation - in production this would query actual events
        return array(
            'success' => true,
            'events' => array(),
            'user_id' => get_current_user_id()
        );
    }
    
    /**
     * REST API Endpoint: Event erstellen
     */
    public function rest_create_event($request) {
        $user_id = get_current_user_id();
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            return new WP_Error('user_not_found', 'Benutzer nicht gefunden', array('status' => 404));
        }
        
        // Get event data from request (JSON body or form parameters)
        $json_params = $request->get_json_params();
        if ($json_params) {
            // Data from JSON body
            $title = sanitize_text_field($json_params['title'] ?? '');
            $start = $json_params['start'] ?? '';
            $end = $json_params['end'] ?? '';
            $location = sanitize_text_field($json_params['location'] ?? '');
            $description = sanitize_textarea_field($json_params['content'] ?? $json_params['summary'] ?? $json_params['description'] ?? '');
            $d_tag = sanitize_text_field($json_params['d'] ?? '');
        } else {
            // Data from form parameters
            $title = sanitize_text_field($request->get_param('title'));
            $start = $request->get_param('start');
            $end = $request->get_param('end');
            $location = sanitize_text_field($request->get_param('location'));
            $description = sanitize_textarea_field($request->get_param('description'));
            $d_tag = sanitize_text_field($request->get_param('d'));
        }
        
        if (empty($title) || empty($start) || empty($end)) {
            return new WP_Error('missing_data', 'Titel, Start und End-Zeit sind erforderlich', array('status' => 400));
        }
        
        // Convert timestamps to ISO strings if they're numeric
        if (is_numeric($start)) {
            $start = date('c', $start); // ISO 8601 format
        }
        if (is_numeric($end)) {
            $end = date('c', $end); // ISO 8601 format
        }
        
        // Get user's calendar identity (with delegation support)
        $identity_manager = new NostrCalendarIdentity();
        $calendar_identity = $identity_manager->get_or_create_identity($user_id);
        
        // Prepare event data for Nostr
        $event_data = [
            'kind' => 31923, // Calendar time-based event (NIP-52)
            'content' => $description ?: '',
            'tags' => [
                ['d', $d_tag ?: 'wp-event-' . time() . '-' . $user_id], // Unique identifier
                ['title', $title],
                ['start', $start],
                ['end', $end]
            ],
            'created_at' => time()
        ];
        
        // Add location if provided
        if (!empty($location)) {
            $event_data['tags'][] = ['location', $location];
        }
        
        // Add WordPress metadata
        $event_data['tags'][] = ['wp_user_id', (string)$user_id];
        $event_data['tags'][] = ['wp_site', site_url()];
        
        // Publish using NostrCalendarPublisher
        $publisher = new NostrCalendarPublisher();
        $result = $publisher->publish_event($event_data, $calendar_identity);
        
        if ($result['success']) {
            return [
                'success' => true,
                'message' => 'Event erfolgreich erstellt und an Nostr-Relays gesendet',
                'event' => $result['event'],
                'relays_published' => $result['relays_published'],
                'user_id' => $user_id,
                'calendar_identity' => $calendar_identity
            ];
        } else {
            return new WP_Error('publish_failed', 'Event-Veröffentlichung fehlgeschlagen', [
                'status' => 500,
                'details' => $result['errors']
            ]);
        }
    }
    
    /**
     * REST API Endpoint: Events erstellen (client-seitige Signatur)
     */
    public function create_event($request) {
        try {
            // Check if event is already signed (from admin interface)
            $event_data = $request->get_json_params();
            
            if (isset($event_data['id']) && isset($event_data['sig'])) {
                // Event is already signed - publish directly
                return $this->publish_signed_event($event_data);
            }
            
            // Event is not signed - this is the WordPress API flow
            // We need to create the event and return it for client-side signing
            return $this->prepare_event_for_signing($event_data, $request);
            
        } catch (Exception $e) {
            return new WP_Error('create_failed', $e->getMessage(), ['status' => 500]);
        }
    }
    
    /**
     * Prepare event data for client-side signing
     */
    private function prepare_event_for_signing($event_data, $request) {
        // Get user identity
        $user_id = get_current_user_id();
        if (!$user_id) {
            // Try SSO token
            $sso_token = $request->get_param('sso_token');
            if ($sso_token) {
                global $nostr_calendar_sso_manager;
                if ($nostr_calendar_sso_manager) {
                    $sso_user = $nostr_calendar_sso_manager->validate_sso_token($sso_token);
                    if ($sso_user) {
                        $user_id = $sso_user['wp_user_id'];
                    }
                }
            }
        }
        
        if (!$user_id) {
            return new WP_Error('unauthorized', 'Authentication required', ['status' => 401]);
        }
        
        // Create event structure for Nostr
        $event_template = [
            'kind' => 31923, // Calendar event kind
            'created_at' => time(),
            'content' => $this->format_event_content($event_data),
            'tags' => $this->build_event_tags($event_data, $user_id)
        ];
        
        // Return event template for client-side signing
        return [
            'success' => true,
            'event_template' => $event_template,
            'user_id' => $user_id,
            'message' => 'Event template created - sign on client side and send back'
        ];
    }

    /**
     * Format event content for Nostr event
     */
    private function format_event_content($event_data) {
        $content = '';
        
        if (!empty($event_data['title'])) {
            $content .= $event_data['title'] . "\n\n";
        }
        
        if (!empty($event_data['description'])) {
            $content .= $event_data['description'] . "\n\n";
        }
        
        if (!empty($event_data['location'])) {
            $content .= "📍 " . $event_data['location'] . "\n";
        }
        
        if (!empty($event_data['start']) && !empty($event_data['end'])) {
            $start_formatted = is_numeric($event_data['start']) ? 
                date('Y-m-d H:i', $event_data['start']) : 
                $event_data['start'];
            $end_formatted = is_numeric($event_data['end']) ? 
                date('Y-m-d H:i', $event_data['end']) : 
                $event_data['end'];
            $content .= "🕐 {$start_formatted} - {$end_formatted}\n";
        }
        
        return trim($content);
    }

    /**
     * Build event tags for Nostr event
     */
    private function build_event_tags($event_data, $user_id) {
        $tags = [];
        
        // Required NIP-52 tags
        if (!empty($event_data['title'])) {
            $tags[] = ['title', sanitize_text_field($event_data['title'])];
        }
        
        if (!empty($event_data['start'])) {
            $start_timestamp = is_numeric($event_data['start']) ? 
                $event_data['start'] : 
                strtotime($event_data['start']);
            $tags[] = ['start', (string)$start_timestamp];
        }
        
        if (!empty($event_data['end'])) {
            $end_timestamp = is_numeric($event_data['end']) ? 
                $event_data['end'] : 
                strtotime($event_data['end']);
            $tags[] = ['end', (string)$end_timestamp];
        }
        
        // Optional tags
        if (!empty($event_data['location'])) {
            $tags[] = ['location', sanitize_text_field($event_data['location'])];
        }
        
        if (!empty($event_data['summary'])) {
            $tags[] = ['summary', sanitize_text_field($event_data['summary'])];
        }
        
        // Status tag
        $status = !empty($event_data['status']) ? $event_data['status'] : 'planned';
        $tags[] = ['status', sanitize_text_field($status)];
        
        // Categories/tags
        if (!empty($event_data['categories'])) {
            $categories = is_array($event_data['categories']) ? 
                $event_data['categories'] : 
                explode(',', $event_data['categories']);
            
            foreach ($categories as $category) {
                $category = trim(sanitize_text_field($category));
                if ($category) {
                    $tags[] = ['t', $category];
                }
            }
        }
        
        // Unique identifier (d tag for replaceable events)
        $d_tag = !empty($event_data['d']) ? 
            sanitize_text_field($event_data['d']) : 
            'wp-event-' . time() . '-' . $user_id;
        $tags[] = ['d', $d_tag];
        
        // WordPress metadata
        $tags[] = ['wp_user_id', (string)$user_id];
        $tags[] = ['wp_site', get_site_url()];
        
        // App identification
        $tags[] = ['app', 'nostr-calendar-wordpress'];
        
        return $tags;
    }
    /**
	 * CORRECTED: Get delegation private key for current user
	 */
	public function get_delegation_private_key($request) {
		try {
			$user_id = get_current_user_id();
			if (!$user_id) {
				return new WP_Error('unauthorized', 'Not authenticated', ['status' => 401]);
			}
			
			// Use global delegation manager OR simple fallback
			global $nostr_calendar_delegation_manager;
			if ($nostr_calendar_delegation_manager && method_exists($nostr_calendar_delegation_manager, 'getDelegationPrivateKey')) {
				$private_key = $nostr_calendar_delegation_manager->getDelegationPrivateKey($user_id);
			} else {
				// Simple fallback - generate deterministic private key
				$seed = "wp-user-private-{$user_id}-" . get_site_url();
				$private_key = hash('sha256', $seed);
			}
			
			if (!$private_key) {
				return new WP_Error('key_error', 'Could not generate delegation private key', ['status' => 500]);
			}
			
			return [
				'success' => true,
				'private_key' => $private_key,
				'user_id' => $user_id,
				'message' => 'Delegation private key retrieved successfully'
			];
			
		} catch (Exception $e) {
			error_log('[NostrCalendar] Delegation private key error: ' . $e->getMessage());
			return new WP_Error('key_error', 'Failed to get delegation private key: ' . $e->getMessage(), ['status' => 500]);
		}
	}
    /**
	 * Get current SSO user from request (helper for delegation endpoint)
	 */
	private function get_current_sso_user($request) {
		// Check SSO token first
		$sso_token = $request->get_param('sso_token');
		
		if ($sso_token) {
			$user = $this->validate_sso_token($sso_token);
			if ($user) {
				return $user;
			}
		}
		
		// Fallback to current logged in user
		return wp_get_current_user();
	}
    /**
	 * Validate SSO token (helper for delegation endpoint)
	 */
	private function validate_sso_token($token) {
		try {
			// Parse token (format: base64_payload.signature)
			$parts = explode('.', $token);
			if (count($parts) !== 2) {
				return false;
			}
			
			$payload_json = base64_decode($parts[0]);
			$payload = json_decode($payload_json, true);
			
			if (!$payload || !isset($payload['wp_user_id']) || !isset($payload['expires'])) {
				return false;
			}
			
			// Check if token is expired
			if (time() > $payload['expires']) {
				return false;
			}
			
			// Get user by ID
			$user = get_user_by('ID', $payload['wp_user_id']);
			if (!$user) {
				return false;
			}
			
			return $user;
			
		} catch (Exception $e) {
			error_log('[NostrCalendar] SSO token validation error: ' . $e->getMessage());
			return false;
		}
	}
    /**
	 * Generate deterministic pubkey for user (must match JavaScript version)
	 */
	private function generateDeterministicPubkey($userId) {
		$input = "wp-user-{$userId}-" . get_site_url();
		return hash('sha256', $input);
	}

}