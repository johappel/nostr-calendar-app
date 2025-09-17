// js/auth/AuthManager.js
// Central authentication manager that coordinates auth plugins

import { authRegistry } from './AuthPluginInterface.js';
import { NostrAuthPlugin } from './NostrAuthPlugin.js';

export class AuthManager {
  constructor(config = {}) {
    this.config = config;
    this.initialized = false;
    this.currentPlugin = null;
    this.uiElements = {};
    this.changeCallbacks = [];
  }

  /**
   * Initialize the auth manager and register available plugins
   */
  async initialize() {
    if (this.initialized) return;

    console.log('[AuthManager] Initializing authentication system');

    // Always register Nostr auth plugin
    const nostrPlugin = new NostrAuthPlugin(this.config.nostr || {});
    authRegistry.register('nostr', nostrPlugin);

    // Conditionally load WordPress auth plugin if SSO is available
    if (this.isWordPressSSoAvailable()) {
      try {
        console.log('[AuthManager] WordPress SSO detected, loading WordPress auth plugin');
        const { WordPressAuthPlugin } = await import('./WordPressAuthPlugin.js');
        const wpPlugin = new WordPressAuthPlugin(this.config.wordpress || {});
        authRegistry.register('wordpress', wpPlugin);
      } catch (error) {
        console.warn('[AuthManager] Failed to load WordPress auth plugin:', error);
      }
    } else {
      console.log('[AuthManager] WordPress SSO not available, using Nostr-only authentication');
    }

    // Initialize all plugins
    for (const plugin of authRegistry.getAll()) {
      try {
        await plugin.initialize();
      } catch (error) {
        console.error(`[AuthManager] Failed to initialize ${plugin.name}:`, error);
      }
    }

    // Find currently active plugin
    await this.refreshActivePlugin();

    this.initialized = true;
    console.log('[AuthManager] Initialization complete');
  }

  /**
   * Setup UI elements and event handlers
   */
  async setupUI(elements, onChange) {
    this.uiElements = elements;
    if (onChange) this.changeCallbacks.push(onChange);

    // Setup logout handler
    if (elements.btnLogout) {
      elements.btnLogout.onclick = async () => {
        await this.logout();
      };
    }

    // Setup plugin-specific UI
    for (const plugin of authRegistry.getAll()) {
      try {
        plugin.setupUI(elements, () => this.onAuthChange());
      } catch (error) {
        console.error(`[AuthManager] UI setup failed for ${plugin.name}:`, error);
      }
    }

    await this.updateUI();
  }

  /**
   * Check if any auth plugin is logged in
   */
  async isLoggedIn() {
    const plugin = await this.getActivePlugin();
    return plugin !== null;
  }

  /**
   * Get current user identity from active plugin
   */
  async getIdentity() {
    const plugin = await this.getActivePlugin();
    return plugin ? await plugin.getIdentity() : null;
  }

  /**
   * Get current user's public key
   */
  async getPublicKey() {
    const plugin = await this.getActivePlugin();
    return plugin ? await plugin.getPublicKey() : null;
  }

  /**
   * Get current user's display name
   */
  async getDisplayName() {
    const plugin = await this.getActivePlugin();
    return plugin ? await plugin.getDisplayName() : null;
  }

  /**
   * Create an event using the active auth plugin
   */
  async createEvent(eventData) {
    const plugin = await this.getActivePlugin();
    if (!plugin) {
      throw new Error('No authentication plugin active');
    }

    return await plugin.createEvent(eventData);
  }

  /**
   * Delete an event using the active auth plugin
   */
  async deleteEvent(eventId) {
    const plugin = await this.getActivePlugin();
    if (!plugin) {
      return { success: false, error: 'No authentication plugin active' };
    }

    try {
      const result = await plugin.deleteEvent(eventId);
      return { success: true, result };
    } catch (error) {
      console.error(`[AuthManager] Delete event failed:`, error);
      return { success: false, error: error.message || 'Delete failed' };
    }
  }

  /**
   * Logout from current auth plugin
   */
  async logout() {
    const plugin = await this.getActivePlugin();
    if (plugin) {
      console.log(`[AuthManager] Logging out from ${plugin.name}`);
      await plugin.logout();
      this.currentPlugin = null;
      await this.onAuthChange();
    }
  }

  /**
   * Get the currently active auth plugin (highest priority logged in)
   */
  async getActivePlugin() {
    if (this.currentPlugin && await this.currentPlugin.isLoggedIn()) {
      return this.currentPlugin;
    }

    await this.refreshActivePlugin();
    return this.currentPlugin;
  }

  /**
   * Refresh the active plugin by checking all registered plugins
   */
  async refreshActivePlugin() {
    const primary = await authRegistry.getPrimary();
    
    if (primary !== this.currentPlugin) {
      const oldPlugin = this.currentPlugin;
      this.currentPlugin = primary;
      
      if (oldPlugin !== primary) {
        console.log(`[AuthManager] Active plugin changed: ${oldPlugin?.name || 'none'} → ${primary?.name || 'none'}`);
        await this.onAuthChange();
      }
    }
  }

  /**
   * Handle authentication state changes
   */
  async onAuthChange() {
    await this.refreshActivePlugin();
    await this.updateUI();
    
    // Notify callbacks
    for (const callback of this.changeCallbacks) {
      try {
        await callback(this.currentPlugin);
      } catch (error) {
        console.error('[AuthManager] Callback error:', error);
      }
    }
  }

  /**
   * Update UI based on current auth state
   */
  async updateUI() {
    if (this.currentPlugin) {
      await this.currentPlugin.updateAuthUI(this.uiElements);
    } else {
      this.updateNoAuthUI();
    }
  }

  /**
   * Update UI for no authentication state
   */
  updateNoAuthUI() {
    const { whoami, btnLogin, btnLogout, btnNew, btnLoginMenu } = this.uiElements;

    if (whoami) whoami.textContent = '';
    if (btnLogout) btnLogout.style.display = 'none';
    if (btnLoginMenu) {
      btnLoginMenu.style.display = 'inline-block';
      btnLoginMenu.classList.remove('hidden'); // Remove hidden class that overrides style
    }
    if (btnLogin) btnLogin.style.display = 'inline-block';
    if (btnNew) {
      btnNew.disabled = true;
      btnNew.title = 'Bitte zuerst einloggen';
    }
  }

  /**
   * Get specific auth plugin by name
   */
  getPlugin(name) {
    return authRegistry.get(name);
  }

  /**
   * Get all registered auth plugins
   */
  getAllPlugins() {
    return authRegistry.getAll();
  }

  /**
   * Check if WordPress SSO is available
   */
  isWordPressSSoAvailable() {
    // Check if we're running in a WordPress environment
    if (typeof window !== 'undefined') {
      // Check for WordPress-specific global variables
      if (window.nostrCalendarWP && window.nostrCalendarWP.sso && window.nostrCalendarWP.sso.enabled) {
        return true;
      }
      
      // Check for WordPress SSO configuration
      if (window.nostrCalendarSSO && window.nostrCalendarSSO.enabled) {
        return true;
      }
      
      // Check for WordPress REST API availability
      if (window.nostrCalendarWP && window.nostrCalendarWP.apiUrl) {
        return true;
      }

      // Check for WordPress SSO session in localStorage
      try {
        const wpSession = localStorage.getItem('wp_sso_session');
        if (wpSession) {
          const session = JSON.parse(wpSession);
          if (session.site_url && Date.now() / 1000 < session.expires) {
            console.log('[AuthManager] WordPress SSO session found in localStorage');
            return true;
          }
        }
      } catch (e) {
        console.debug('[AuthManager] Error checking WordPress session:', e);
      }

      // Check if we're on a WordPress site by looking for typical WordPress indicators
      const isWordPressSite = window.location.href.includes('/wp-') || 
                             window.location.href.includes('wordpress') ||
                             document.querySelector('meta[name="generator"]')?.content.includes('WordPress') ||
                             document.querySelector('link[href*="wp-content"]') !== null;
      
      if (isWordPressSite) {
        console.log('[AuthManager] WordPress environment detected');
        return true;
      }
    }
    
    return false;
  }

  /**
   * Get all active (logged in) auth plugins
   */
  async getActivePlugins() {
    return await authRegistry.getActive();
  }

  /**
   * Check if a specific feature is supported by current auth
   */
  async supports(feature) {
    const plugin = await this.getActivePlugin();
    return plugin ? plugin.supports(feature) : false;
  }

  /**
   * Add a callback for auth state changes
   */
  onChange(callback) {
    this.changeCallbacks.push(callback);
  }

  /**
   * Clean up resources
   */
  async destroy() {
    for (const plugin of authRegistry.getAll()) {
      try {
        await plugin.destroy();
      } catch (error) {
        console.error(`[AuthManager] Destroy failed for ${plugin.name}:`, error);
      }
    }
    
    this.currentPlugin = null;
    this.changeCallbacks = [];
  }
}

// Create global auth manager instance
export const authManager = new AuthManager();