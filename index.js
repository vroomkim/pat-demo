import http from 'http';
import fs from 'fs';
import * as dotenv from 'dotenv';
dotenv.config()

import IssuerDataFetcher from './lib/IssuerDataFetcher.js';
import TokenRequestCreator from './lib/TokenRequestCreator.js';
import TokenRedemption from './lib/TokenRedemption.js';

const issuerDataFetcher = new IssuerDataFetcher();
const tokenRequestCreator = new TokenRequestCreator();
const tokenRedemption = new TokenRedemption();

if (!process.env.TOKEN_DICT_URL) {
    console.error('Please create a .env file from .env.sample.')
    process.exit(1);
}

issuerDataFetcher.fetchIssuerData(process.env.TOKEN_DICT_URL).then(issuerInfo => {
    http.createServer(function (req, res) {
    
        // Check if header exists first
        let validationResult = { isValid: false };
        if ('authorization' in req.headers) {
             validationResult = tokenRedemption.validateAuthToken(issuerInfo, req.headers['authorization']);
        }

        if (validationResult.isValid) {
            console.log('200 - Authenticated request, path=' + req.url);

            let html = fs.readFileSync("html/success200.html", "utf8");
            
            // Inject Data into HTML
            html = html.replace('AUTH_HEADER', req.headers['authorization']);
            
            // Format token data for display
            const tokenJson = JSON.stringify(validationResult.tokenData, null, 4);
            html = html.replace('TOKEN_INFO_JSON', tokenJson);

            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.write(html);
            res.end();

        } else {
            console.log('401 - Unauthenticated request, path=' + req.url);
            
            // Generate Challenge
            var tokenRequests = [];
            // We need to capture these values to display them on the HTML page
            let challengeDetails = {}; 

            for (var i = 0; i < 1; i++) {
                var tokenRequest = tokenRequestCreator.createTokenRequest(issuerInfo.issuer_name, process.env.INCLUDE_RANDOM_NONCE || true, process.env.ORIGIN_SCOPE);
                tokenRedemption.registerTokenRequestForRedemption(Buffer.from(tokenRequest, 'base64'));
                
                const challengeString = 'PrivateToken challenge=' + tokenRequest + ', token-key=' + issuerInfo.issuer_public_key_base64;
                tokenRequests.push(challengeString);

                // Store details for HTML display
                challengeDetails = {
                    challenge_string: challengeString,
                    token_key: issuerInfo.issuer_public_key_base64,
                    raw_request_base64: tokenRequest,
                    origin_scope: process.env.ORIGIN_SCOPE || "Not Set",
                    issuer_name: issuerInfo.issuer_name
                };
            }

            let html = fs.readFileSync("html/challenge401.html", "utf8");

            // Replace placeholders in HTML
            html = html.replace('CHALLENGE_STRING_VAL', challengeDetails.challenge_string);
            html = html.replace('ISSUER_NAME_VAL', challengeDetails.issuer_name);
            html = html.replace('ORIGIN_SCOPE_VAL', challengeDetails.origin_scope);
            html = html.replace('TOKEN_KEY_VAL', challengeDetails.token_key);
            
            // If there was a failed validation attempt, show the error
            if (validationResult.error) {
                 html = html.replace('ERROR_MSG', `<div style="color:red; font-weight:bold;">Validation Failed: ${validationResult.error}</div>`);
            } else {
                 html = html.replace('ERROR_MSG', '');
            }

            res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'WWW-Authenticate': tokenRequests.join(', ') });
            res.write(html);
            res.end();
        }
    }).listen(process.env.NODE_PORT);
});
