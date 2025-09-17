// Import der bereits funktionierenden nostr.js
import { client } from '../../../js/nostr.js';

class NostrCalendarAdmin {
    constructor() {
        this.init();
    }

    async init() {
        this.bindEvents();
        await this.loadCalendarIdentity();
    }

    bindEvents() {
        // Event creation form - PREVENT default form submission
        const eventForm = document.getElementById('nostr-event-form');
        if (eventForm) {
            eventForm.addEventListener('submit', this.handleEventSubmit.bind(this));
        }

        // Generate new identity button
        const generateBtn = document.getElementById('generate-identity');
        if (generateBtn) {
            generateBtn.addEventListener('click', this.generateNewIdentity.bind(this));
        }

        // Test publish button
        const testBtn = document.getElementById('test-publish');
        if (testBtn) {
            testBtn.addEventListener('click', this.testPublish.bind(this));
        }
    }

    /**
     * Handle event form submission - USE EXISTING NOSTR.JS WORKFLOW
     */
    async handleEventSubmit(event) {
        event.preventDefault(); // CRITICAL: Prevent GET request
        event.stopPropagation();

        try {
            const formData = new FormData(event.target);
            
            // Convert form data to app-compatible format
            const eventData = this.convertFormDataToEventData(formData);
            
            // Use existing nostr.js publish method
            const result = await client.publish(eventData);
            
            if (result && result.signed) {
                this.showMessage('Event published successfully via Nostr relays!', 'success');
                this.displayPublishResults(result);
                document.getElementById('nostr-event-form').reset();
            } else {
                throw new Error('Publishing failed - no signed event returned');
            }

        } catch (error) {
            console.error('Event submission failed:', error);
            this.showMessage('Failed to create event: ' + error.message, 'error');
        }
    }

    /**
     * Convert form data to format expected by existing nostr.js publish()
     */
    convertFormDataToEventData(formData) {
        const title = formData.get('title') || '';
        const content = formData.get('content') || '';
        const location = formData.get('location') || '';
        const categories = formData.get('categories') || '';
        
        // Convert date/time to timestamps
        const startDate = formData.get('start_date');
        const startTime = formData.get('start_time');
        const endDate = formData.get('end_date');
        const endTime = formData.get('end_time');
        
        let start = 0;
        let end = 0;
        
        if (startDate && startTime) {
            start = Math.floor(new Date(`${startDate}T${startTime}`).getTime() / 1000);
        }
        
        if (endDate && endTime) {
            end = Math.floor(new Date(`${endDate}T${endTime}`).getTime() / 1000);
        } else if (start) {
            // Default: 1 hour duration
            end = start + 3600;
        }

        // Format tags array
        const tags = [];
        if (categories) {
            categories.split(',').forEach(cat => {
                const cleanCat = cat.trim();
                if (cleanCat) {
                    tags.push(cleanCat);
                }
            });
        }

        // Return data in format expected by nostr.js publish()
        return {
            title,
            content,
            start,
            end,
            location,
            tags,
            status: 'planned',
            summary: content.substring(0, 100) // Short summary from content
        };
    }

    /**
     * Generate new identity - simplified, just use nostr.js login
     */
    async generateNewIdentity() {
        try {
            // Use existing nostr.js login method
            const result = await client.login();
            
            if (result && result.pubkey) {
                this.showMessage('New identity generated: ' + result.method, 'success');
                this.updateIdentityDisplay(result);
            } else {
                throw new Error('Failed to generate identity');
            }
        } catch (error) {
            console.error('Failed to generate identity:', error);
            this.showMessage('Failed to generate identity: ' + error.message, 'error');
        }
    }

    /**
     * Test publish using existing nostr.js
     */
    async testPublish() {
        try {
            const testData = {
                title: 'Test Event from WordPress Admin',
                content: 'This is a test event created from WordPress admin interface at ' + new Date().toISOString(),
                start: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
                end: Math.floor(Date.now() / 1000) + 7200,   // 2 hours from now
                location: 'WordPress Admin Panel',
                tags: ['test', 'wordpress', 'nostr-calendar'],
                status: 'planned'
            };

            const result = await client.publish(testData);
            
            if (result && result.signed) {
                this.showMessage('Test event published successfully!', 'success');
                this.displayPublishResults(result);
            } else {
                throw new Error('Test publish failed');
            }

        } catch (error) {
            console.error('Test publish failed:', error);
            this.showMessage('Test publish failed: ' + error.message, 'error');
        }
    }

    /**
     * Load calendar identity - simplified
     */
    async loadCalendarIdentity() {
        try {
            // Check if nostr client is already logged in
            if (client.pubkey && client.signer) {
                this.updateIdentityDisplay({
                    pubkey: client.pubkey,
                    method: client.signer.type
                });
            }
        } catch (error) {
            console.debug('No existing identity found:', error);
        }
    }

    /**
     * Update identity display in UI
     */
    updateIdentityDisplay(identity) {
        const pubkeyDisplay = document.getElementById('current-pubkey-display');
        if (pubkeyDisplay && identity) {
            pubkeyDisplay.innerHTML = `
                <strong>Identity Active:</strong><br>
                Method: ${identity.method || 'unknown'}<br>
                Pubkey: ${identity.pubkey ? identity.pubkey.substring(0, 16) + '...' : 'none'}
            `;
        }
    }

    /**
     * Display publish results
     */
    displayPublishResults(result) {
        const resultsDiv = document.getElementById('publish-results');
        if (!resultsDiv) return;

        let html = '<h4>Publishing Results:</h4>';
        
        if (result.signed) {
            html += '<div class="success">';
            html += '<strong>✅ Event signed and published to Nostr relays</strong><br>';
            html += `<strong>Event ID:</strong> ${result.signed.id}<br>`;
            html += `<strong>Kind:</strong> ${result.signed.kind}<br>`;
            html += `<strong>Created:</strong> ${new Date(result.signed.created_at * 1000).toLocaleString()}`;
            html += '</div>';
        }
        
        resultsDiv.innerHTML = html;
    }

    /**
     * Show message to user
     */
    showMessage(message, type = 'info') {
        const messageDiv = document.getElementById('admin-messages') || this.createMessageDiv();
        
        const messageElement = document.createElement('div');
        messageElement.className = `notice notice-${type} is-dismissible`;
        messageElement.innerHTML = `<p>${message}</p>`;
        
        messageDiv.appendChild(messageElement);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (messageElement.parentNode) {
                messageElement.remove();
            }
        }, 5000);
    }

    /**
     * Create message container if it doesn't exist
     */
    createMessageDiv() {
        const messageDiv = document.createElement('div');
        messageDiv.id = 'admin-messages';
        messageDiv.style.marginBottom = '20px';
        
        const container = document.querySelector('.wrap') || document.body;
        container.insertBefore(messageDiv, container.firstChild);
        
        return messageDiv;
    }
}

 // Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new NostrCalendarAdmin();
});


