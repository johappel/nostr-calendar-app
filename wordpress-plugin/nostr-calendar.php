<?php
/**
 * Plugin Name: Nostr Calendar
 * Plugin URI: https://github.com/johappel/nostr-calendar-app
 * Description: Ein WordPress Plugin für dezentrale Kalender-Events über das Nostr-Protokoll mit optionaler SSO-Integration
 * Version: 1.0.0
 * Author: johappel
 * Author URI: https://github.com/johappel
 * License: MIT
 * Text Domain: nostr-calendar
 * Domain Path: /languages
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('NOSTR_CALENDAR_VERSION', '1.0.0');
define('NOSTR_CALENDAR_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('NOSTR_CALENDAR_PLUGIN_URL', plugin_dir_url(__FILE__));

// Include required classes
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-rest-api.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-identity.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-nostr-publisher.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-simple-crypto.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/shortcodes.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-nostr-ajax-handler.php';

// Include modular classes (to be created)
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-admin-interface.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-sso-manager.php';
require_once NOSTR_CALENDAR_PLUGIN_DIR . 'includes/class-delegation-manager.php';

// Composer autoload for Nostr PHP library
if (file_exists(NOSTR_CALENDAR_PLUGIN_DIR . 'vendor/autoload.php')) {
    require_once NOSTR_CALENDAR_PLUGIN_DIR . 'vendor/autoload.php';
}

/**
 * Main Plugin Class - Modularized Version
 */
class NostrCalendarUnified {
    
    private $sso_enabled = false;
    private $shared_secret = '8afbcf017eee556056251b040a3e70f9e78720580a12b27d5f166bf750b3fe7f';
    private $calendar_app_url = 'https://test1.rpi-virtuell.de/nostr-calendar';
    
    // Module instances
    private $admin_interface;
    private $sso_manager;
    private $delegation_manager;
    
    public function __construct() {
        // Initialize modules
        $this->admin_interface = new NostrCalendarAdminInterface();
        $this->sso_manager = new NostrCalendarSSOManager($this->shared_secret, $this->calendar_app_url);
        $this->delegation_manager = new NostrCalendarDelegationManager();
        
        // Make modules available globally for admin interface
        global $nostr_calendar_sso_manager, $nostr_calendar_delegation_manager;
        $nostr_calendar_sso_manager = $this->sso_manager;
        $nostr_calendar_delegation_manager = $this->delegation_manager;
        
        // WordPress hooks
        add_action('init', [$this, 'init']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_scripts']);
        
        // Plugin lifecycle hooks
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        
        // Check if SSO is enabled
        $this->sso_enabled = get_option('nostr_calendar_sso_enabled', false);
    }
    
    public function init() {
        // Always initialize REST API - it handles both SSO and non-SSO authentication
        new NostrCalendarRestAPI();
        
        // Initialize user identity management
        new NostrCalendarIdentity();
        
        // Load text domain
        load_plugin_textdomain('nostr-calendar', false, dirname(plugin_basename(__FILE__)) . '/languages');

        // Rewrite rule to serve single-page calendar app at /nostr-calendar
        add_rewrite_rule('^nostr-calendar/(.*)$', 'index.php?nostr_calendar=1&nostr_calendar_path=$matches[1]', 'top');
        add_rewrite_rule('^nostr-calendar/?$', 'index.php?nostr_calendar=1', 'top');
        add_filter('query_vars', function($vars) { 
            $vars[] = 'nostr_calendar'; 
            $vars[] = 'nostr_calendar_path'; 
            return $vars; 
        });
        add_action('template_redirect', [$this, 'serve_calendar_page']);
        
        // Initialize shortcodes
        $this->init_shortcodes();
        
        // Initialize SSO features if enabled
        if ($this->sso_enabled) {
            $this->sso_manager->init();
        }
        
        // Initialize delegation AJAX endpoints
        $this->delegation_manager->init_ajax_endpoints();
        
        // Initialize publisher and AJAX handler
        global $nostr_calendar_publisher, $nostr_calendar_ajax_handler;
        $nostr_calendar_publisher = new NostrCalendarPublisher();
        $nostr_calendar_ajax_handler = new NostrCalendarAjaxHandler();
    }
    
    public function enqueue_scripts() {
        // Only load on pages where calendar is displayed
        if (is_page() || is_single() || has_shortcode(get_post()->post_content ?? '', 'nostr_calendar')) {
            wp_enqueue_script(
                'nostr-calendar-app',
                NOSTR_CALENDAR_PLUGIN_URL . 'assets/js/app.js',
                [],
                NOSTR_CALENDAR_VERSION,
                true
            );
            
            wp_enqueue_style(
                'nostr-calendar-style',
                NOSTR_CALENDAR_PLUGIN_URL . 'assets/css/style.css',
                [],
                NOSTR_CALENDAR_VERSION
            );
            
            // Base configuration
            $config = [
                'apiUrl' => rest_url('nostr-calendar/v1/'),
                'nonce' => wp_create_nonce('wp_rest'),
                'currentUser' => wp_get_current_user(),
                'isLoggedIn' => is_user_logged_in(),
                'relays' => get_option('nostr_calendar_relays', [
                    'wss://relay.damus.io',
                    'wss://nos.lol'
                ])
            ];
            
            // Add SSO config if enabled
            if ($this->sso_enabled) {
                $config['sso'] = [
                    'enabled' => true,
                    'wpSiteUrl' => get_site_url(),
                    'loginUrl' => wp_login_url(),
                    'logoutUrl' => wp_logout_url()
                ];
            }
            
            // Localize script with WordPress data
            wp_localize_script('nostr-calendar-app', 'nostrCalendarWP', $config);
        }
    }
    
    public function admin_enqueue_scripts($hook) {
        if (strpos($hook, 'nostr-calendar') !== false) {
            wp_enqueue_script('jquery-ui-tabs');
            wp_enqueue_style('wp-jquery-ui-dialog');
            
            wp_enqueue_script(
                'nostr-calendar-admin',
                NOSTR_CALENDAR_PLUGIN_URL . 'assets/js/admin.js',
                ['jquery', 'jquery-ui-tabs'],
                NOSTR_CALENDAR_VERSION,
                true
            );
            
            wp_enqueue_style(
                'nostr-calendar-admin',
                NOSTR_CALENDAR_PLUGIN_URL . 'assets/css/admin.css',
                [],
                NOSTR_CALENDAR_VERSION
            );
            
            // Localize admin script with data
            wp_localize_script('nostr-calendar-admin', 'nostrCalendarAdmin', [
                'nonce' => wp_create_nonce('nostr_calendar_admin'),
                'delegationNonce' => wp_create_nonce('nostr_calendar_delegation'),
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'siteUrl' => get_site_url()
            ]);
        }
    }
    
    public function add_admin_menu() {
        add_options_page(
            __('Nostr Calendar Einstellungen', 'nostr-calendar'),
            __('Nostr Calendar', 'nostr-calendar'),
            'manage_options',
            'nostr-calendar',
            [$this, 'admin_page']
        );
    }
    
    public function admin_page() {
        // Delegate to admin interface module
        $this->admin_interface->render_admin_page();
    }
    
    public function serve_calendar_page() {
        if (get_query_var('nostr_calendar')) {
            $path = get_query_var('nostr_calendar_path');
            
            // If there's a specific file path requested
            if ($path) {
                $this->serve_static_file($path);
                return;
            }
            
            // No specific path - serve main index.html
            $this->serve_main_app();
        }
    }
    
    private function serve_static_file($path) {
        // Clean the path to prevent directory traversal
        $path = ltrim($path, '/');
        $path = str_replace(['../', './'], '', $path);
        
        // Define allowed files and their locations
        $file_candidates = [
            'wp-sso.html' => [
                NOSTR_CALENDAR_PLUGIN_DIR . 'assets/wp-sso.html',
            ],
            'wp-logout' => [
                NOSTR_CALENDAR_PLUGIN_DIR . 'assets/wp-logout.html',
            ],
            'index.html' => [
                NOSTR_CALENDAR_PLUGIN_DIR . 'assets/index.html',
            ]
        ];
        
        // Check if the requested file is in our allowed list
        if (isset($file_candidates[$path])) {
            foreach ($file_candidates[$path] as $file) {
                if (file_exists($file)) {
                    $this->serve_file($file, $path);
                    return;
                }
            }
        }
        
        // For any other files, try to serve them from the assets directory
        $generic_file = NOSTR_CALENDAR_PLUGIN_DIR . 'assets/' . $path;
        if (file_exists($generic_file) && is_file($generic_file)) {
            // Basic security check - only allow certain file types
            $allowed_extensions = ['html', 'css', 'js', 'json', 'txt'];
            $extension = pathinfo($path, PATHINFO_EXTENSION);
            
            if (in_array($extension, $allowed_extensions)) {
                $this->serve_file($generic_file, $path);
                return;
            }
        }
        
        // File not found or not allowed
        status_header(404);
        echo '<h1>Not Found</h1><p>The requested file was not found.</p>';
        exit;
    }
    
    private function serve_file($file, $path) {
        $content_types = [
            'html' => 'text/html; charset=utf-8',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'txt' => 'text/plain'
        ];
        
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $content_type = $content_types[$extension] ?? 'text/plain';
        
        header('Content-Type: ' . $content_type);
        readfile($file);
        exit;
    }
    
    private function serve_main_app() {
        $candidates = [
            NOSTR_CALENDAR_PLUGIN_DIR . 'assets/index.html',
            dirname(NOSTR_CALENDAR_PLUGIN_DIR) . '/index.html'  // Root of nostr-calendar-app
        ];

        foreach ($candidates as $file) {
            if (file_exists($file)) {
                // Inject SSO configuration if enabled
                $content = file_get_contents($file);
                
                if ($this->sso_enabled) {
                    $sso_config = json_encode([
                        'enabled' => true,
                        'wpSiteUrl' => get_site_url(),
                        'features' => ['auto_login', 'server_side_publishing']
                    ]);
                    
                    $content = str_replace(
                        '</head>',
                        '<script>window.nostrCalendarSSO = ' . $sso_config . ';</script></head>',
                        $content
                    );
                }
                
                header('Content-Type: text/html; charset=utf-8');
                echo $content;
                exit;
            }
        }

        // If not found, return 404
        status_header(404);
        echo '<h1>Nostr Calendar</h1><p>Frontend not found in plugin folder.</p>';
        exit;
    }
    
    private function init_shortcodes() {
        add_shortcode('nostr_calendar', [$this, 'calendar_shortcode']);
    }
    
    public function calendar_shortcode($atts) {
        $atts = shortcode_atts([
            'sso' => 'auto',
            'height' => '600px',
            'view' => 'month'
        ], $atts);
        
        $sso_attr = '';
        if ($atts['sso'] === 'true' || ($atts['sso'] === 'auto' && $this->sso_enabled)) {
            $sso_attr = ' data-sso="enabled"';
        }
        
        return sprintf(
            '<div id="nostr-calendar-embed" style="height: %s;" data-view="%s"%s></div>',
            esc_attr($atts['height']),
            esc_attr($atts['view']),
            $sso_attr
        );
    }
    
    public function activate() {
        // Flush rewrite rules on activation
        flush_rewrite_rules();
    }
    
    public function deactivate() {
        // Flush rewrite rules on deactivation
        flush_rewrite_rules();
    }
}

// Initialize the plugin
new NostrCalendarUnified();

/**
 * Enqueue admin scripts and styles
 */
function nostr_calendar_admin_enqueue_scripts($hook) {
    // Only load on our plugin pages
    if (strpos($hook, 'nostr-calendar') === false) {
        return;
    }
    
    // Enqueue nostr-tools from CDN
    wp_enqueue_script(
        'nostr-tools',
        'https://unpkg.com/nostr-tools@2.5.2/lib/index.js',
        [],
        '2.5.2',
        true
    );
    
    // Enqueue our admin script
    wp_enqueue_script(
        'nostr-calendar-admin',
        plugin_dir_url(__FILE__) . 'admin/js/admin.js',
        ['nostr-tools'],
        '1.0.0',
        true
    );
    
    // Localize script with AJAX data
    wp_localize_script('nostr-calendar-admin', 'nostr_calendar_admin', [
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('nostr_calendar_admin')
    ]);
}
add_action('admin_enqueue_scripts', 'nostr_calendar_admin_enqueue_scripts');