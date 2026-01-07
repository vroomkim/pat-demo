'use strict';

import crypto from 'crypto';

class TokenRedemption {

    constructor() {
        this.activeContexts = {};
    }

    registerTokenRequestForRedemption(tokenRequest) {
        var contextHash = crypto.createHash('sha256').update(tokenRequest).digest();
        this.activeContexts[contextHash.toString('hex')] = 1;
    }

    /**
     * Validates the token and returns a structured result object.
     * Returns: { isValid: boolean, error: string, tokenData: object }
     */
    validateAuthToken(issuerInfo, authorizationHeader) {
        let result = {
            isValid: false,
            error: null,
            tokenData: null
        };

        if (!authorizationHeader || authorizationHeader === '') {
            result.error = "No Authorization header present";
            return result;
        }
    
        var authToken;
        // Arrives as "Authorization: PrivateToken token=..."
        const strings = authorizationHeader.split(" ");
        for (var i = 0; i < strings.length; i++) {
            var s = strings[i];
            if (s.startsWith('token=')) {
                authToken = s.replace('token=', '');
                break;
            }
        }
    
        if (!authToken) {
            result.error = "Token not found in Authorization header";
            return result;
        }
    
        /**
         * Token structure according to spec (Token Type 2 - RSA Blind Signature)
         */
         const buf = Buffer.from(authToken, 'base64');
         
         // Parse the token components for display
         try {
             const tokenType = buf.readInt16BE(0);
             const nonce = buf.subarray(2, 34);
             const context = buf.subarray(34, 66);
             const keyId = buf.subarray(66, 98);
             const authenticator = buf.subarray(98);

             result.tokenData = {
                 token_type: tokenType,
                 nonce_hex: nonce.toString('hex'),
                 context_hex: context.toString('hex'),
                 key_id_hex: keyId.toString('hex'),
                 authenticator_hex: authenticator.toString('hex').substring(0, 32) + "..." // Truncate for display
             };

             // Only token type 2 is supported
             if (tokenType !== 2) {
                 result.error = "Unsupported Token Type (only type 2 is supported)";
                 return result;
             }
         
             // context is defined as SHA256(valid token request)
             const contextHex = context.toString('hex');
             if (this.activeContexts[contextHex]) {
                 delete this.activeContexts[contextHex];
             } else {
                 console.error('Double redemption attempt or invalid context detected!');
                 result.error = "Double redemption or invalid context";
                 return result;
             }
             
             // Verify the token signature
             const verifiableData = buf.subarray(0, 98);
             const isVerified = crypto.verify(
                 null,
                 verifiableData,
                 {
                    key: issuerInfo.issuer_public_key_pem
                 },
                 authenticator
             );
    
             if (isVerified) {
                 result.isValid = true;
             } else {
                 result.error = "Cryptographic verification failed";
             }

         } catch (e) {
             result.error = "Malformed token data";
         }

         return result;
    }
}

export default TokenRedemption;
