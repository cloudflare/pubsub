// Copyright (c) 2022 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// PubSubMessage represents an incoming PubSub message.
// The message includes metadata about the broker, the client, and the payload
// itself.
export interface PubSubMessage {
	// Message ID
	readonly mid: number;
	// MQTT broker FQDN
	readonly broker: string;
	// The MQTT topic the message was sent on.
	readonly topic: string;
	// The client ID of the client that published this message.
	readonly clientId: string;
	// The unique identifier (JWT ID) used by the client to authenticate, if token
	// auth was used.
	readonly jti?: string;
	// A Unix timestamp (seconds from Jan 1, 1970), set when the Pub/Sub Broker
	// received the message from the client.
	readonly receivedAt: number;
	// An (optional) string with the MIME type of the payload, if set by the
	// client.
	readonly contentType: string;
	// Set to 1 when the payload is a UTF-8 string
	// https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901063
	readonly payloadFormatIndicator: number;
	// Pub/Sub (MQTT) payloads can be UTF-8 strings, or byte arrays.
	// You can use payloadFormatIndicator to inspect this before decoding.
	payload: string | Uint8Array;
}

// JsonWebKey extended by kid parameter
export interface JsonWebKeyWithKid extends JsonWebKey {
	// Key Identifier of the JWK
	readonly kid: string;
}

const SIGNATURE_FORMAT = "NODE-ED25519";

// isValidBrokerRequest authenticates an incoming request to ensure it is
// signed by the provided brokerPublicKeys
//
// It returns true when the incoming request is signed by the corresponding
// private key, with each private key unique to each Pub/Sub broker.
//
// It returns false in all other cases.
export async function isValidBrokerRequest(
	req: Request,
	publicKeys: string
): Promise<boolean> {
	if (req.method !== "POST") {
		return false;
	}

	let signature = req.headers.get("X-Signature-Ed25519");
	let timestamp = req.headers.get("X-Signature-Timestamp");
	let keyId = req.headers.get("X-Signature-Key-Id");

	if (signature === null || timestamp === null || keyId === null) {
		return false;
	}

	let body = await req.clone().text();
	let alg = { name: SIGNATURE_FORMAT, namedCurve: SIGNATURE_FORMAT };

	try {
		// Convert the base64 encoded signature
		let signatureBuffer = Uint8Array.from(atob(signature), (c) =>
			c.charCodeAt(0)
		);

		// Deserialize the encoded list of JWKs associated with our Pub/Sub Broker
		let publicJWKList: Array<JsonWebKeyWithKid> = JSON.parse(publicKeys).keys;

		// Lookup JWK by Key Identifier
		let publicJWK = publicJWKList.find((jwk) => jwk.kid === keyId);

		// No JWK in the Set, request can not be verified
		if (!publicJWK) {
			return false;
		}

		// Import the public key from our Broker (in JWK format) so we can verify the
		// request is from _our_ Broker, and not an untrusted third-party
		let publicKey = await crypto.subtle.importKey(
			"jwk",
			publicJWK,
			alg,
			false,
			["verify"]
		);

		if (
			await crypto.subtle.verify(
				SIGNATURE_FORMAT,
				publicKey,
				signatureBuffer,
				new TextEncoder().encode(timestamp + body)
			)
		) {
			return true;
		}
	} catch (e) {
		console.log(e);
		return false;
	}

	return false;
}
