// js/auth/WordPressAuthPlugin.js
// WordPress SSO authentication plugin

import { AuthPluginInterface } from './AuthPluginInterface.js';

export class WordPressAuthPlugin extends AuthPluginInterface {
  constructor(config = {}) {
    super(config);
    this.name = 'wordpress';
    this.displayName = 'WordPress SSO';
    this.wpSiteUrl = config.wpSiteUrl || 'https://test1.rpi-virtuell.de';
    this.currentSession = null;
  }

  async initialize() {
    console.log('[WordPressAuth] Initializing WordPress SSO plugin');
    
    // Check for SSO success parameters first
    try {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('wp_sso') === 'success') {
        console.log('[WordPressAuth] SSO success detected in URL');
        
        // Check if we have a valid session in localStorage
        const sessionData = localStorage.getItem('wp_sso_session');
        if (sessionData) {
          try {
            const session = JSON.parse(sessionData);
            if (Date.now() / 1000 < session.expires) {
              // Normalize calendar_identity.pubkey to match server algorithm if not using a shared blog identity
              try {
                if (session.user && session.user.id && !session.shared_identity && !this.isDelegatedIdentity(session.calendar_identity)) {
                  const siteUrl = session.site_url || session.wp_site_url || this.wpSiteUrl;
                  const expectedPub = await this.generateDeterministicPubkey(session.user.id, siteUrl);
                  if (!session.calendar_identity) session.calendar_identity = {};
                  if (!session.calendar_identity.pubkey || session.calendar_identity.pubkey !== expectedPub) {
                    session.calendar_identity.pubkey = expectedPub;
                    localStorage.setItem('wp_sso_session', JSON.stringify(session));
                  }
                } else if (this.isDelegatedIdentity(session.calendar_identity)) {
                  console.debug('[WordPressAuth] Detected delegated calendar_identity, skipping pubkey normalization');
                }
              } catch (e) {
                console.debug('[WordPressAuth] Error normalizing session pubkey during init:', e);
              }

              this.currentSession = session;
              console.log('[WordPressAuth] Valid SSO session found, user logged in:', session.user.username);
            }
          } catch (e) {
            console.warn('[WordPressAuth] Invalid session data in localStorage');
          }
        }
        
        // Show notification
        this.showSSONotification(urlParams.get('user'));
        
        // Clean URL
        const url = new URL(window.location);
        url.searchParams.delete('wp_sso');
        url.searchParams.delete('user');
        window.history.replaceState({}, '', url);
      }
    } catch (e) {
      console.warn('[WordPressAuth] Error checking URL params:', e);
    }

    // Check for WordPress SSO session in localStorage if not already set
    if (!this.currentSession) {
      await this.checkLocalSession();
    }
  }

  async isLoggedIn() {
    const session = await this.getSession();
    return session !== null;
  }

  async getIdentity() {
    const session = await this.getSession();
    if (!session) {
      return null;
    }

    // Handle different session structures
    const user = session.user || session.wp_user;
    const calendarIdentity = session.calendar_identity;
    
    if (!user) {
      console.error('[WordPressAuth] getIdentity: No user data in session');
      return null;
    }

    // Build base identity
    const identity = {
      pubkey: calendarIdentity?.pubkey || await this.generateDeterministicPubkey(user.id, session.site_url || session.wp_site_url),
      user: user,
      wpUser: user, // backwards compatibility
      calendarIdentity: calendarIdentity || {
        pubkey: await this.generateDeterministicPubkey(user.id, session.site_url || session.wp_site_url),
        name: user.display_name || user.username,
        about: `WordPress user from ${session.site_url || session.wp_site_url}`,
        nip05: `${user.username}@${new URL(session.site_url || session.wp_site_url).hostname}`
      },
      displayName: calendarIdentity?.name || user.display_name || user.username,
      provider: 'wordpress',
      method: 'wordpress_sso',
      supports: {
        signing: false,
        eventCreation: true,
        serverSidePublishing: true
      }
    };

    // WICHTIG: Delegation-Daten vom WordPress-Endpoint übernehmen
    if (calendarIdentity?.delegation) {
      console.log('[WordPressAuth] Found delegation data in calendar identity:', calendarIdentity.delegation);
      
      // Delegation-Informationen hinzufügen
      identity.delegation = {
        // Raw delegation tag (für Event-Publishing)
        raw: calendarIdentity.delegation.raw,
        // Parsed delegation data
        delegatee: identity.pubkey, // Der delegierte Pubkey (WordPress User)
        delegator: calendarIdentity.delegation.delegator, // Der delegierende Pubkey
        conditions: calendarIdentity.delegation.conds,
        signature: calendarIdentity.delegation.sig,
        // Zusätzliche Metadaten
        saved_by: calendarIdentity.delegation.saved_by,
        saved_at: calendarIdentity.delegation.saved_at,
        delegator_profile: calendarIdentity.delegation.delegator_profile
      };

      // Signing-Unterstützung für delegierte Identitäten
      identity.supports.signing = true;
      identity.supports.delegation = true;
      
      // Display-Name vom Delegator übernehmen falls vorhanden
      if (calendarIdentity.delegation.delegator_profile?.name) {
        identity.displayName = calendarIdentity.delegation.delegator_profile.name;
      }

      console.log('[WordPressAuth] Identity with delegation:', {
        pubkey: identity.pubkey,
        delegator: identity.delegation.delegator,
        conditions: identity.delegation.conditions
      });
    }

    console.debug('[WordPressAuth] getIdentity result:', identity);
    return identity;
  }

  async login(credentials = {}) {
    const { token } = credentials;
    
    if (!token) {
      throw new Error('WordPress SSO token required for login');
    }

    try {
      // For client-side SSO, we process the token directly
      const tokenParts = token.split('.');
      if (tokenParts.length !== 2) {
        throw new Error('Ungültiges Token-Format');
      }

      const [tokenData, signature] = tokenParts;
      let payload;
      
      try {
        payload = JSON.parse(atob(tokenData));
      } catch (e) {
        throw new Error('Token konnte nicht dekodiert werden');
      }

      // Check if token is expired
      if (Date.now() / 1000 > payload.expires) {
        throw new Error('Token ist abgelaufen');
      }

      // Create session data
      const sessionData = {
        type: 'wordpress_sso',
        token: token,
        user: {
          id: payload.wp_user_id,
          username: payload.wp_username,
          email: payload.wp_email,
          display_name: payload.wp_display_name,
          roles: payload.wp_roles
        },
        site_url: payload.wp_site_url,
        timestamp: payload.timestamp,
        expires: payload.expires,
        authenticated_at: Date.now(),
        // Generate a calendar identity for this WordPress user
        calendar_identity: {
            pubkey: await this.generateDeterministicPubkey(payload.wp_user_id, payload.wp_site_url),
            name: payload.wp_display_name || payload.wp_username,
            about: `WordPress user from ${payload.wp_site_url}`,
            nip05: `${payload.wp_username}@${new URL(payload.wp_site_url).hostname}`
          }
      };

      // Store in localStorage and memory
      localStorage.setItem('wp_sso_session', JSON.stringify(sessionData));
      this.currentSession = sessionData;

      console.log('[WordPressAuth] Login successful:', sessionData.user.username);
      
      return {
        success: true,
        method: 'wordpress_sso',
        user: sessionData.user,
        calendarIdentity: sessionData.calendar_identity,
        provider: 'wordpress'
      };
    } catch (error) {
      console.error('[WordPressAuth] Login failed:', error);
      throw error;
    }
  }

  async logout() {
    console.log('[WordPressAuth] Logging out from WordPress SSO');
    
    // Clear localStorage
    localStorage.removeItem('wp_sso_session');
    this.currentSession = null;
  }

  async createEvent(eventData) {
    if (!await this.isLoggedIn()) {
      throw new Error('Not logged in to WordPress SSO');
    }

    try {
      console.log('[WordPressAuth] Creating event using WordPress delegation without nos2x');
      
      // Get current identity (mit Delegation-Daten)
      const identity = await this.getIdentity();
      
      // Import nostr client
      const { client } = await import('../nostr.js');
      
      // WICHTIG: Bei WordPress-Delegation NICHT client.login() verwenden
      if (identity?.delegation?.raw) {
        console.log('[WordPressAuth] Using WordPress delegation - bypassing nostr.js login completely');
        
        // Prepare event data
        const nostrEventData = {
          title: eventData.title || '',
          content: eventData.content || '',
          start: this.convertToTimestamp(eventData.start),
          end: this.convertToTimestamp(eventData.end),
          location: eventData.location || '',
          tags: this.parseEventTags(eventData),
          status: 'planned',
          summary: (eventData.content || eventData.title || '').substring(0, 100)
        };

        // Add delegation tag from WordPress
        try {
          const delegationData = JSON.parse(identity.delegation.raw);
          if (Array.isArray(delegationData) && delegationData[0] === 'delegation') {
            nostrEventData.delegationTag = delegationData;
            console.log('[WordPressAuth] Delegation tag added from WordPress:', delegationData);
          }
        } catch (e) {
          console.warn('[WordPressAuth] Failed to parse delegation data:', e);
        }

        // Create temporary delegation-aware signer that doesn't use nos2x
        const wpDelegationSigner = {
          type: 'wordpress_delegation',
          getPublicKey: async () => identity.delegation.delegatee,
          signEvent: async (evt) => {
            // Use WordPress delegation for signing
            return await this.signEventWithWordPressDelegation(evt, identity.delegation);
          }
        };

        // Temporarily override client signer
        const originalSigner = client.signer;
        client.signer = wpDelegationSigner;

        try {
          console.log('[WordPressAuth] Publishing via WordPress delegation signer');
          const result = await client.publish(nostrEventData);
          
          if (result && result.signed) {
            console.log('[WordPressAuth] Event published with WordPress delegation:', result.signed.id);
            
            // Verify delegation tag was included
            const delegationTag = result.signed.tags?.find(tag => tag[0] === 'delegation');
            if (delegationTag) {
              console.log('[WordPressAuth] Delegation tag confirmed in published event:', delegationTag);
            }
            
            return {
              ok: true,
              event: result.signed,
              message: 'Event published with WordPress delegation'
            };
          } else {
            throw new Error('No signed event returned from WordPress delegation');
          }
        } finally {
          // Restore original signer
          client.signer = originalSigner;
        }
        
      } else {
        console.log('[WordPressAuth] No delegation found - using standard nostr client');
        
        // Standard publishing ohne Delegation - nur hier client.login() verwenden
        if (!client.signer) {
          await client.login();
        }
        
        const nostrEventData = {
          title: eventData.title || '',
          content: eventData.content || '',
          start: this.convertToTimestamp(eventData.start),
          end: this.convertToTimestamp(eventData.end),
          location: eventData.location || '',
          tags: this.parseEventTags(eventData),
          status: 'planned',
          summary: (eventData.content || eventData.title || '').substring(0, 100)
        };

        const result = await client.publish(nostrEventData);
        
        if (result && result.signed) {
          return {
            ok: true,
            event: result.signed,
            message: 'Event published via standard signing'
          };
        } else {
          throw new Error('No signed event returned from standard signing');
        }
      }

    } catch (error) {
      console.error('[WordPressAuth] Event creation error:', error);
      throw error;
    }
  }

  /**
   * Convert date string or timestamp to unix timestamp
   */
  convertToTimestamp(dateInput) {
    if (!dateInput) return Math.floor(Date.now() / 1000);
    
    // If already a number (timestamp), return it
    if (typeof dateInput === 'number') {
      return Math.floor(dateInput);
    }
    
    // If string, try to parse
    if (typeof dateInput === 'string') {
      const date = new Date(dateInput);
      if (!isNaN(date.getTime())) {
        return Math.floor(date.getTime() / 1000);
      }
    }
    
    // Fallback to current time
    return Math.floor(Date.now() / 1000);
  }

  /**
   * Parse event tags from various input formats
   */
  parseEventTags(eventData) {
    const tags = [];
    
    // Handle tags array
    if (Array.isArray(eventData.tags)) {
      eventData.tags.forEach(tag => {
        if (typeof tag === 'string' && tag.trim()) {
          tags.push(tag.trim());
        }
      });
    }
    
    // Handle categories string
    if (typeof eventData.categories === 'string' && eventData.categories.trim()) {
      eventData.categories.split(',').forEach(cat => {
        const cleanCat = cat.trim();
        if (cleanCat) {
          tags.push(cleanCat);
        }
      });
    }
    
    // Add WordPress-specific tags
    tags.push('wordpress');
    tags.push('wp-calendar');
    
    return tags;
  }

  /**
   * ENHANCED: Get real delegation private key from WordPress with verification
   */
  async getDelegationPrivateKeyFromWordPress() {
    try {
      const wpSiteUrl = this.currentSession.site_url || this.currentSession.wp_site_url;
      let apiUrl = `${wpSiteUrl}/wp-json/nostr-calendar/v1/delegation-private-key`;

      // Add SSO token if available
      const storedSession = localStorage.getItem('wp_sso_session');
      if (storedSession) {
        const sessionData = JSON.parse(storedSession);
        if (sessionData.token && Date.now() / 1000 < sessionData.expires) {
          apiUrl += `?sso_token=${encodeURIComponent(sessionData.token)}`;
        }
      }

      console.log('[WordPressAuth] Requesting delegation private key from WordPress API');

      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('[WordPressAuth] WordPress private key API failed:', response.status, errorText);
        throw new Error(`WordPress private key API failed: ${response.status}`);
      }

      const result = await response.json();
      console.log('[WordPressAuth] WordPress API response:', result);
      
      if (result.success && result.private_key) {
        console.log('[WordPressAuth] Received real delegation private key from WordPress');
        return result.private_key;
      } else {
        throw new Error(result.message || 'No private key returned from WordPress');
      }
      
    } catch (error) {
      console.error('[WordPressAuth] Failed to get delegation private key from WordPress:', error);
      throw error;
    }
  }

  /**
   * Sign event using WordPress delegation with real private key from backend
   */
  async signEventWithWordPressDelegation(event, delegation) {
    try {
      console.log('[WordPressAuth] Signing event with REAL WordPress delegation key');
      
      // Load nostr-tools for local signing
      const toolsModule = await import('https://esm.sh/nostr-tools@2.8.1/pure');
      const tools = toolsModule;

      // KRITISCH: Event muss mit dem Delegatee-Pubkey signiert werden
      const targetPubkey = delegation.delegatee; // WordPress User Pubkey
      
      console.log('[WordPressAuth] Target pubkey for signing:', targetPubkey);

      // REAL: Get actual delegation private key from WordPress backend
      let realPrivateKey;
      try {
        realPrivateKey = await this.getDelegationPrivateKeyFromWordPress();
        console.log('[WordPressAuth] Got private key from WordPress:', realPrivateKey ? 'YES' : 'NO');
        
        if (!realPrivateKey || typeof realPrivateKey !== 'string' || realPrivateKey.length !== 64) {
          throw new Error('Invalid private key received from WordPress: ' + (typeof realPrivateKey) + ' length=' + (realPrivateKey?.length || 'undefined'));
        }
        
        // CRITICAL: Verify the private key produces the expected pubkey
        const privateKeyBytes = new Uint8Array(realPrivateKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const derivedPubkey = tools.getPublicKey(privateKeyBytes);
        
        console.log('[WordPressAuth] Key verification:', {
          expectedPubkey: targetPubkey,
          derivedPubkey: derivedPubkey,
          match: derivedPubkey === targetPubkey
        });
        
        if (derivedPubkey !== targetPubkey) {
          console.warn('[WordPressAuth] Private key does not produce expected pubkey, using fallback');
          throw new Error('Private key mismatch');
        }
        
        console.log('[WordPressAuth] Private key verification successful');
        
      } catch (error) {
        console.warn('[WordPressAuth] Failed to get/verify real private key, using corrected fallback:', error);
        // CORRECTED: Use the SAME algorithm as PHP backend
        realPrivateKey = await this.generateMatchingPrivateKey(targetPubkey);
      }
      
      // Convert hex string to bytes
      let privateKeyBytes;
      if (typeof realPrivateKey === 'string' && realPrivateKey.length === 64) {
        privateKeyBytes = new Uint8Array(realPrivateKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      } else {
        throw new Error('Invalid private key format: ' + typeof realPrivateKey + ' length=' + (realPrivateKey?.length || 'undefined'));
      }

      // FINAL VERIFICATION: Double-check the key produces the correct pubkey
      const finalPubkey = tools.getPublicKey(privateKeyBytes);
      if (finalPubkey !== targetPubkey) {
        throw new Error(`Final pubkey verification failed: ${finalPubkey} !== ${targetPubkey}`);
      }

      // Ensure event has the correct pubkey before signing
      if (!event.pubkey || event.pubkey !== targetPubkey) {
        event.pubkey = targetPubkey;
        console.log('[WordPressAuth] Set event pubkey to WordPress user:', targetPubkey);
      }

      // Generate event ID with correct pubkey
      if (!event.id) {
        try {
          event.id = tools.getEventHash(event);
          console.log('[WordPressAuth] Generated event ID with WordPress pubkey:', event.id);
        } catch (e) {
          console.warn('[WordPressAuth] Could not generate event ID:', e);
        }
      }

      console.log('[WordPressAuth] Signing with verified WordPress delegation private key');

      // Sign the event with the VERIFIED delegation private key
      const signedEvent = tools.finalizeEvent(event, privateKeyBytes);
      
      // Final verification
      if (signedEvent.pubkey !== targetPubkey) {
        console.error('[WordPressAuth] FINAL VERIFICATION FAILED!', {
          expected: targetPubkey,
          actual: signedEvent.pubkey
        });
        throw new Error('Final signed event pubkey verification failed');
      }
      
      console.log('[WordPressAuth] Event signed successfully with verified WordPress delegation:', {
        id: signedEvent.id,
        pubkey: signedEvent.pubkey,
        kind: signedEvent.kind,
        tags: signedEvent.tags.length,
        delegationTag: signedEvent.tags.find(t => t[0] === 'delegation') ? 'PRESENT' : 'MISSING'
      });
      
      return signedEvent;

    } catch (error) {
      console.error('[WordPressAuth] WordPress delegation signing failed:', error);
      throw new Error('WordPress delegation signing failed: ' + error.message);
    }
  }

  /**
   * CORRECTED: Generate private key using EXACT same algorithm as PHP backend
   */
  async generateMatchingPrivateKey(targetPubkey) {
    const session = await this.getSession();
    const userId = session?.user?.id;
    const siteUrl = session?.site_url || session?.wp_site_url;
    
    if (!userId || !siteUrl) {
      throw new Error('Cannot generate key without user ID and site URL');
    }

    // Load nostr-tools
    const toolsModule = await import('https://esm.sh/nostr-tools@2.8.1/pure');
    const tools = toolsModule;

    // EXACTLY match PHP backend: "wp-user-private-{$userId}-" . get_site_url()
    const seed = `wp-user-private-${userId}-${siteUrl}`;
    
    console.log('[WordPressAuth] Using EXACT PHP algorithm with seed:', seed);
    
    // Use same SHA-256 as PHP hash('sha256', $seed)
    const encoder = new TextEncoder();
    const data = encoder.encode(seed);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const privateKeyBytes = new Uint8Array(digest);
    
    // Convert to hex string (like PHP)
    const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Verify this produces the target pubkey
    const derivedPubkey = tools.getPublicKey(privateKeyBytes);
    
    console.log('[WordPressAuth] Generated key verification:', {
      seed: seed,
      privateKeyHex: privateKeyHex.substring(0, 16) + '...',
      derivedPubkey: derivedPubkey,
      targetPubkey: targetPubkey,
      match: derivedPubkey === targetPubkey
    });
    
    if (derivedPubkey === targetPubkey) {
      console.log('[WordPressAuth] SUCCESS: Generated matching private key');
      return privateKeyHex;
    } else {
      throw new Error(`Generated private key does not produce target pubkey: ${derivedPubkey} !== ${targetPubkey}`);
    }
  }

  async deleteEvent(eventId) {
    if (!await this.isLoggedIn()) {
      throw new Error('Not logged in to WordPress SSO');
    }

    try {
      // Get the WordPress site URL from session
      const wpSiteUrl = this.currentSession.site_url || this.currentSession.wp_site_url;
      let apiUrl = `${wpSiteUrl}/wp-json/nostr-calendar/v1/events/${encodeURIComponent(eventId)}`;

      // Add SSO token to request if available
      const fetchOptions = {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        }
      };

      // Try to use SSO token for authentication
      const storedSession = localStorage.getItem('wp_sso_session');
      if (storedSession) {
        try {
          const sessionData = JSON.parse(storedSession);
          if (sessionData.token && Date.now() / 1000 < sessionData.expires) {
            apiUrl += `?sso_token=${encodeURIComponent(sessionData.token)}`;
          }
        } catch (e) {
          console.debug('[WordPressAuth] Error parsing stored session');
        }
      }

      const response = await fetch(apiUrl, fetchOptions);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[WordPressAuth] Event deletion failed:', response.status, errorText);
        throw new Error(`Failed to delete event: ${response.status} ${errorText}`);
      }

      const result = await response.json();

      return {
        ok: true,
        message: result.message || 'Event deleted successfully'
      };

    } catch (error) {
      console.error('[WordPressAuth] Event deletion error:', error);
      throw error;
    }
  }

  // async getEvents() { 
  //   if (!await this.isLoggedIn()) {
  //     throw new Error('Not logged in to WordPress SSO');
  //   }

  //   try {
  //     // Get the WordPress site URL from session
  //     const wpSiteUrl = this.currentSession?.site_url || this.currentSession?.wp_site_url || this.wpSiteUrl;
  //     let apiUrl = `${wpSiteUrl}/wp-json/nostr-calendar/v1/events`;

  //     // Add SSO token to request if available
  //     const fetchOptions = {
  //       method: 'GET',
  //       headers: {
  //         'Content-Type': 'application/json'
  //       }
  //     };

  //     // Try to use SSO token for authentication
  //     const storedSession = localStorage.getItem('wp_sso_session');
  //     if (storedSession) {
  //       try {
  //         const sessionData = JSON.parse(storedSession);
  //         if (sessionData.token && Date.now() / 1000 < sessionData.expires) {
  //           apiUrl += `?sso_token=${encodeURIComponent(sessionData.token)}`;
  //         }
  //       } catch (e) {
  //         console.debug('[WordPressAuth] Error parsing stored session');
  //       }
  //     }

  //     const response = await fetch(apiUrl, fetchOptions);

  //     if (!response.ok) {
  //       const errorText = await response.text();
  //       console.error('[WordPressAuth] Getting events failed:', response.status, errorText);
  //       throw new Error(`Failed to get events: ${response.status} ${errorText}`);
  //     }

  //     const result = await response.json();

  //     // Convert WordPress events to the format expected by the calendar
  //     const events = result.events ? Object.values(result.events) : [];
  //     return events;

  //   } catch (error) {
  //     console.error('[WordPressAuth] Get events error:', error);
  //     throw error;
  //   }
  // }

  async updateAuthUI(elements) {
    const { whoami, btnLogin, btnLogout, btnNew, btnLoginMenu } = elements;
    
    
    if (this.currentSession) {
      // Show WordPress user info 
      if (whoami) {
        const identity = await this.getIdentity();
        console.debug('[WordPressAuth] Updating UI for logged in user:', identity);
        if (identity) {
          whoami.innerHTML = `
            <div style="text-align: left;">
              <div><strong>📅 Calendar Identity:</strong> ${identity.displayName}</div>
              <div style="font-size: 0.85em; color: #666;">WordPress User: ${identity.user.display_name || identity.user.username}</div>
              <div style="font-size: 0.75em; color: #999;">${identity.pubkey.slice(0, 16)}...</div>
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
    // WordPress SSO doesn't need manual UI setup
    // Login is handled via external WordPress site redirects
    console.log('[WordPressAuth] UI setup - WordPress SSO uses external login flow');
  }

  async getPublicKey() {
    const identity = await this.getIdentity();
    return identity?.pubkey || null;
  }

  async getDisplayName() {
    const identity = await this.getIdentity();
    return identity?.displayName || null;
  }

  supports(feature) {
    switch (feature) {
      case 'event_creation':
      case 'server_side_publishing':
        return true;
      case 'signing':
      case 'direct_publishing':
        return false;
      default:
        return false;
    }
  }

  getPriority() {
    return 20; // Higher priority than Nostr auth when available
  }

  // Helper methods
  async getSession() {
    if (this.currentSession) {
      return this.currentSession;
    }
    
    return await this.checkSession();
  }

  async checkSession() {
    // First check localStorage for WordPress SSO session
    const localSession = await this.checkLocalSession();
    if (localSession) {
      return localSession;
    }
    
    // Check WordPress site directly via REST API
    try {
      const fetchOptions = {
        credentials: 'include'
      };
      
      // If we have a stored session with token, include it as query parameter
      // (more reliable than headers for WordPress REST API)
      let apiUrl = `${this.wpSiteUrl}/wp-json/nostr-calendar/v1/me`;
      const storedSession = localStorage.getItem('wp_sso_session');
      console.debug('[WordPressAuth] Checking WordPress session via API',storedSession?'with stored session':'without stored session');
      if (storedSession) {
        try {
          const sessionData = JSON.parse(storedSession);
          if (sessionData.token && Date.now() / 1000 < sessionData.expires) {
            // Use query parameter instead of header for better WordPress compatibility
            apiUrl += `?sso_token=${encodeURIComponent(sessionData.token)}`;
          }
        } catch (e) {
          console.debug('[WordPressAuth] Error parsing stored session');
        }
      }else{
        console.debug('[WordPressAuth] No stored session found');
        return null;
      }
      
      const response = await fetch(apiUrl, fetchOptions);
      
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          // Create session from WordPress data
          const sessionData = {
            type: 'wordpress_direct',
            user: data.user,
            site_url: data.site_url,
            calendar_identity: data.calendar_identity,
            authenticated_at: Date.now(),
            expires: Math.floor(Date.now() / 1000) + (8 * 3600) // 8 hours from now
          };
          
          this.currentSession = sessionData;
          localStorage.setItem('wp_sso_session', JSON.stringify(sessionData));
          
          return sessionData;
        }
      }
    } catch (e) {
      console.debug('[WordPressAuth] No direct WordPress session available');
    }
    
    // No session found
    this.currentSession = null;
    return null;
  }

  async checkLocalSession() {
    try {
      const sessionData = localStorage.getItem('wp_sso_session');
      if (!sessionData) {
        return null;
      }

      const session = JSON.parse(sessionData);
      
      // Check if session is expired
      if (Date.now() / 1000 > session.expires) {
        console.log('[WordPressAuth] Session expired, removing');
        localStorage.removeItem('wp_sso_session');
        return null;
      }

      // Session is valid
      // Ensure calendar_identity.pubkey matches deterministic algorithm
      try {
        if (session.user && session.user.id && !this.isDelegatedIdentity(session.calendar_identity)) {
          const siteUrl = session.site_url || session.wp_site_url || this.wpSiteUrl;
          const expectedPub = await this.generateDeterministicPubkey(session.user.id, siteUrl);
          if (!session.calendar_identity) session.calendar_identity = {};
          if (!session.calendar_identity.pubkey || session.calendar_identity.pubkey !== expectedPub) {
            session.calendar_identity.pubkey = expectedPub;
            localStorage.setItem('wp_sso_session', JSON.stringify(session));
            console.log('[WordPressAuth] Normalized local session pubkey for user:', session.user.username);
          }
        } else if (this.isDelegatedIdentity(session.calendar_identity)) {
          console.debug('[WordPressAuth] Detected delegated calendar_identity, skipping pubkey normalization');
        }
      } catch (e) {
        console.debug('[WordPressAuth] Error normalizing session pubkey:', e);
      }

      this.currentSession = session;
      console.log('[WordPressAuth] Found valid local session for:', session.user.username);
      return session;
      
    } catch (e) {
      console.warn('[WordPressAuth] Error checking local session:', e);
      localStorage.removeItem('wp_sso_session');
      return null;
    }
  }

  async generateDeterministicPubkey(userId, siteUrl) {
    // Generate deterministic pubkey matching PHP's hash('sha256', $input)
    const input = `wp-user-${userId}-${siteUrl}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(input);

    // Use WebCrypto to compute SHA-256
    const digest = await crypto.subtle.digest('SHA-256', data);

    // Convert ArrayBuffer to lowercase hex string
    const bytes = new Uint8Array(digest);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }

    // Ensure 64-character lowercase hex (32 bytes)
    return hex.toLowerCase().slice(0, 64).padEnd(64, '0');
  }

  // Detect a delegated (NIP-26) calendar identity to avoid overwriting delegated pubkeys
  isDelegatedIdentity(calendarIdentity) {
    if (!calendarIdentity || typeof calendarIdentity !== 'object') return false;
    // common markers for delegation; be permissive
    const markers = [
      'delegation',
      'delegated_by',
      'nip26',
      'delegate',
      'delegate_sig',
      'delegator',
      'delegate_pubkey',
      'delegation_sig'
    ];
    for (const k of markers) {
      if (calendarIdentity[k]) return true;
    }
    return false;
  }

  showSSONotification(username) {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed; top: 20px; right: 20px; z-index: 10000;
      background: #4CAF50; color: white; padding: 15px 20px;
      border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      font-family: system-ui, sans-serif; font-size: 14px;
    `;
    notification.innerHTML = `
      ✅ <strong>WordPress SSO erfolgreich!</strong><br>
      Angemeldet als: ${username || 'WordPress User'}
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 5000);
  }

  async destroy() {
    await this.logout();
    this.currentSession = null;
  }
}