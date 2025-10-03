// js/auth/AuthManager.js
// Central authentication manager that coordinates auth plugins

import { authRegistry } from './AuthPluginInterface.js';
import { NostrAuthPlugin } from './NostrAuthPlugin.js';
import { b64 } from '../utils.js';
import { Config } from '../config.js';

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

    // Use the centralized toEventTemplate to create the event structure
    const { evt } = this.toEventTemplate(eventData);
    
    // Let the plugin handle the actual signing and publishing
    // Pass the formatted event to all plugins
    return await plugin.createEvent(evt);
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
    // Debug: Show all active plugins with priorities
    const allActive = await authRegistry.getActive();
    console.debug('[AuthManager] Active plugins:', allActive.map(p => `${p.name} (priority: ${p.getPriority()})`).join(', '));
  
    const primary = await authRegistry.getPrimary();
    
    if (primary !== this.currentPlugin) {
      const oldPlugin = this.currentPlugin;
      this.currentPlugin = primary;
      
      if (oldPlugin !== primary) {
        console.log(`[AuthManager] Active plugin changed: ${oldPlugin?.name || 'none'} → ${primary?.name || 'none'}${primary ? ` (priority: ${primary.getPriority()})` : ''}`);
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
    console.log('[AuthManager] Updating UI', this.uiElements);
    console.log('[AuthManager] UI elements keys:', Object.keys(this.uiElements)); 
    console.log('[AuthManager] UI current plugin:', this.currentPlugin);
    
    // Check if UI elements are available
    if (!this.uiElements || Object.keys(this.uiElements).length === 0) {
      console.debug('[AuthManager] UI elements not yet initialized, skipping UI update');
      return;
    }
    if (this.currentPlugin) {
      await this.currentPlugin.updateAuthUI(this.uiElements);
      const sidebarwhoami = document.querySelector('#sidebar-whoami');
      if (sidebarwhoami && this.uiElements.whoami) {
        sidebarwhoami.innerHTML = this.uiElements.whoami.innerHTML || '';
      }
      
      const is_logged_in = await this.getPublicKey();
      if (is_logged_in !== null) {
        const logoutSection = document.querySelector('.sidebar-section.logout');
        if (logoutSection) {
          logoutSection.classList.remove('hidden');
        }
        
      }else{
        const logoutSection = document.querySelector('.sidebar-section.logout');  
        if (logoutSection) {
          logoutSection.classList.add('hidden');
        }
      }
    
    } else {
      this.updateNoAuthUI();
      const logoutSection = document.querySelector('.sidebar-section.logout');  
      if (logoutSection) {
        logoutSection.classList.add('hidden');
      }
    }
  }

  /**
   * Update UI for no authentication state
   */
  updateNoAuthUI() {
    // Check if UI elements are available
    if (!this.uiElements || Object.keys(this.uiElements).length === 0) {
      console.debug('[AuthManager] UI elements not yet initialized, skipping no-auth UI update');
      return;
    }
    
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
      if (window.NostrSignerConfig && window.NostrSignerConfig.enabled) {
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

  /**
   * Create an event template for calendar events (Kind 31923)
   * @param {Object} data - Event data
   * @returns {Object} Event template with evt and d properties
   */
  toEventTemplate(data) {
    const tags = [
      ['title', data.title],
      ['start', String(data.start)],
      ['end', String(data.end)],
      ['status', data.status || 'planned'],
    ];
    if (data.summary) tags.push(['summary', data.summary]);
    if (data.location) tags.push(['location', data.location]);
    if (data.image) tags.push(['image', data.image]);
    
    // Handle tags array properly - ensure each tag is a string
    if (Array.isArray(data.tags)) {
      for (const t of data.tags) {
        const v = String(t).trim();
        if (v) tags.push(['t', v]);
      }
    }
    
    const d = data.d || b64((data.url || '') + '|' + data.title + '|' + data.start);
    tags.push(['d', d]);
    
    // Add app tag if available (imported from utils)
    if (Array.isArray(Config.appTag)) tags.push(Config.appTag);
    
    return {
      evt: {
        kind: 31923,
        created_at: Math.floor(Date.now() / 1000),
        tags,
        content: data.content || ''
      },
      d
    };
  }
}

// Create global auth manager instance
export const authManager = new AuthManager();