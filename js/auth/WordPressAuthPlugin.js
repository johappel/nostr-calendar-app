// js/auth/WordPressAuthPlugin.js
// WordPress SSO authentication plugin

import { AuthPluginInterface } from './AuthPluginInterface.js';
import { client } from '../nostr.js';


export class WordPressAuthPlugin extends AuthPluginInterface {
  constructor(config = {}) {
    super(config);
    this.name = 'wordpress';
    this.displayName = 'WordPress SSO';
    this.currentSession = null;
    this.client = client;
    
    // Create WordPress signer object that implements the signer interface
    this.wordpressSigner = {
      type: 'wordpress',
      getPublicKey: async () => {
        const identity = await this.getIdentity();
        return identity?.user?.pubkey || null;
      },
      signEvent: async (event) => {
        // Use WordPress nostr_sign method
        return await window.WP_NostrTools.nostr_sign(
          event,
          'user',
          {
            signPayload: {
              source: 'nostr-calendar-app',
              kind: event.kind
            }
          }
        );
      },
      // Additional metadata for WordPress signer
      provider: 'wordpress',
      wordpress: true
    };
  }

  async initialize() {
    console.log('[WordPressAuth] Initializing WordPress SSO plugin');
    const userData = localStorage.getItem('wp_session');
    if (userData) {
      this.currentSession = JSON.parse(userData);
      console.log('[WordPressAuth] Restored session from localStorage');
    }

    // Check for WordPress SSO session in localStorage if not already set
    if (!this.currentSession) {
      await this.checkLocalSession();
    }

    // Set WordPress signer in global client if session is active
    if (this.currentSession) {
      const pubkey = this.currentSession.user?.pubkey;
      if (pubkey) {
        console.log('[WordPressAuth] Setting WordPress signer in global client');
        this.client.signer = this.wordpressSigner;
        this.client.pubkey = pubkey;
        this.client.signerType = 'wordpress';
      }
    }

    // Clean URL
    const url = new URL(window.location);
    window.history.replaceState({}, '', url);

  }

  async isLoggedIn() {
    const session = await this.getSession();
    return session !== null;
  }

  async getIdentity() {
    return await this.getSessionIdentity();

  }

  async login(credentials = {}) {
    // Redirect zu WordPress Login
    const loginUrl = window.NostrSignerConfig?.loginUrl || '/wp-login.php';
    const redirectTo = credentials.redirectTo || window.location.href;
    window.location.href = `${loginUrl}?redirect_to=${encodeURIComponent(redirectTo)}`;
  }

  async logout() {
    // Clean up global client signer if it's WordPress
    if (this.client.signer?.type === 'wordpress') {
      console.log('[WordPressAuth] Removing WordPress signer from global client');
      this.client.signer = null;
      this.client.pubkey = null;
      this.client.signerType = null;
    }
    
    // Session-Cleanup
    this.currentSession = null;
    localStorage.removeItem('wp_session');
    
    // Redirect zu WordPress Logout
    const logoutUrl = window.NostrSignerConfig?.logoutUrl || '/wp-login.php?action=logout';
    window.location.href = logoutUrl;
  }
  async createEvent(eventData) {
    if (!await this.isLoggedIn()) {
      throw new Error('Nicht bei WordPress SSO angemeldet');
    }
    try {
      console.debug('[WordPressAuth] sending event to:', eventData, window.NostrSignerConfig?.defaultRelays || ['wss://relay.damus.io']) ;
      // WordPress-Signierung über nostr-app.js
      const result = await window.WP_NostrTools.nostr_send(
        eventData,
        'user', // WordPress-Benutzer-Schlüssel
        window.NostrSignerConfig?.defaultRelays || ['wss://relay.damus.io'],
        {
          publish: true,
          signPayload: {
            source: 'nostr-calendar-app',
            wordpress_user_id: this.currentSession?.user?.id
          }
        }
      );
      console.log('[WordPressAuth] Event published successfully:', result);

      return {
        success: true,
        event: result.event,
        relayResults: result.results
      };

    } catch (error) {
      console.error('[WordPressAuth] Event creation failed:', error);
      throw new Error(`Event-Erstellung fehlgeschlagen: ${error.message}`);
    }
  }

  // delete calendar event by ID
  async deleteEvent(eventId) {
    if (!await this.isLoggedIn()) {
      throw new Error('Nicht bei WordPress SSO angemeldet');
    }

    try {
      // NIP-9 DELETE Event erstellen
      const deleteEvent = {
        kind: 5,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['e', eventId], // Referenz auf zu löschendes Event
          ['k', '31923']  // Kind des zu löschenden Events
        ],
        content: 'Event gelöscht'
      };

      const result = await window.WP_NostrTools.nostr_send(
        deleteEvent,
        'user',
        window.NostrSignerConfig?.defaultRelays || ['wss://relay.damus.io'],
        { publish: true }
      );

      return {
        success: true,
        event: result.event,
        relayResults: result.results
      };

    } catch (error) {
      console.error('[WordPressAuth] Event deletion failed:', error);
      throw new Error(`Event-Löschung fehlgeschlagen: ${error.message}`);
    }
  }

  
  async updateAuthUI(elements) {
    // Check if elements are provided
    if (!elements) {
      console.debug('[WordPressAuth] No UI elements provided, skipping UI update');
      return;
    }
    
    const { whoami, btnLogin, btnLogout, btnNew, btnLoginMenu } = elements;

    if (this.currentSession) {
      console.log('[WordPressAuth] Logged in via WordPress SSO', this.currentSession);

      // Show WordPress user info
      if (whoami) {
        const identity = await this.getIdentity();
        console.debug('[WordPressAuth] Updating UI for logged in user:', identity);
        if (identity) {
          whoami.innerHTML = `
            <div style="text-align: left;">
              <div style="margin-bottom: 4px;">
                <img src="${identity.user?.avatar || ''}" alt="Avatar" style="width: 32px; height: 32px; border-radius: 16px; vertical-align: middle; margin-right: 8px;">
                <strong>${identity.user?.display_name || identity.user?.username}</strong>
              </div>
              <div style="font-size: 0.85em; color: #666;">Blog: ${identity.blog?.display_name || identity.user?.username}</div>
              <div style="font-size: 0.75em; color: #999;">${identity.user?.npub.slice(0, 16) || identity.blog?.npub.slice(0, 16)}...</div>
            </div>
          `;
        }
      }

      // Hide login elements, show logout
      if (btnLoginMenu) btnLoginMenu.style.display = 'none';
      if (btnLogin) btnLogin.style.display = 'none';
      if (btnLogout) {
        btnLogout.style.display = 'inline-block';
        btnLogout.classList.remove('hidden');
      }
      if (btnNew) {
        btnNew.style.display = 'inline-block';
        btnNew.disabled = false;
        btnNew.title = 'Neuen Termin anlegen';
      }
    } else {
      // WordPress not active - don't interfere with other auth methods
      // The NostrAuthPlugin should handle the login UI when WordPress SSO is not active
      console.log('[WordPressAuth] Not logged in, letting other auth plugins handle UI');
    }
  }

  setupUI(elements, onChange) {
    // remove .sidebar-section.authsection if exists
    const authSection = document.querySelector('.sidebar-section.auth');
    if (authSection) {
      authSection.style.display = 'none';
    }

    console.log('[WordPressAuth] UI setup - WordPress SSO uses external login flow');
  }

  async getPublicKey() {
    const identity = await this.getIdentity();
    return identity?.user?.pubkey || null;
  }

  async getDisplayName() {
    const identity = await this.getIdentity();
    return identity?.user?.display_name || null;
  }

  /**
   * Get priority for this auth plugin
   * WordPress SSO should have higher priority than Nostr when active
   * @returns {number} Priority (higher = preferred)
   */
  getPriority() {
    // WordPress SSO has priority 20 (higher than Nostr's 10)
    // This ensures WordPress is the primary auth when logged in
    return 20;
  }

  // Helper methods
  async getSession() {
    console.log('[WordPressAuth] Retrieving session');
    if (this.currentSession) {
      return this.currentSession;
    }else{
      // get session from localStorage if available else fetch from /me
      const storedSession = localStorage.getItem('wp_session');
      if (storedSession) {
        this.currentSession = JSON.parse(storedSession);
        
        // Set signer in global client if we have a pubkey
        const pubkey = this.currentSession?.user?.pubkey;
        if (pubkey && (!this.client.signer || this.client.signer.type !== 'wordpress')) {
          console.log('[WordPressAuth] Setting WordPress signer from cached session');
          this.client.signer = this.wordpressSigner;
          this.client.pubkey = pubkey;
          this.client.signerType = 'wordpress';
        }
        
        return this.currentSession;
      }else{
        // fetch from /me endpoint
        console.log('[WordPressAuth] Fetching session data from /me');
        const userData = await window.WP_NostrTools.nostr_me();
        console.log('[WordPressAuth] Fetched session data from /me:', userData);
        if (userData) {
          const data = {
            user: {},
            calendarIdentity: {}
          };
          data.user = {
            pubkey: userData.user.pubkey.hex,
            npub: userData.user.pubkey.npub,
            username: userData.user.username,
            display_name: userData.user.display_name || userData.user.username,
            avatar: userData.user.avatar_url || ''
          };
          data.blog = {
            pubkey: userData.blog.pubkey.hex,
            npub: userData.blog.pubkey.npub,
            display_name: userData.blog.blog_name || 'Blog',
          };
          this.currentSession = data;
          localStorage.setItem('wp_session', JSON.stringify(data));
          
          // Set signer in global client
          const pubkey = data.user?.pubkey;
          if (pubkey) {
            console.log('[WordPressAuth] Setting WordPress signer from /me response');
            this.client.signer = this.wordpressSigner;
            this.client.pubkey = pubkey;
            this.client.signerType = 'wordpress';
          }
          
          return data;
        }
      } 
    }
    return null;
  }
  async getSessionIdentity() {
    const session = await this.getSession();
    if (!session) {
      return null;
    }
    
    return session;
  }

  async checkLocalSession() {
    console.log('[WordPressAuth] Checking local session');
    return await this.getSession();
  }


}
