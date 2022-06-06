"use strict";

/// <reference types="@cloudflare/workers-types" />

const SIGNATURE_FORMAT = "NODE-ED25519";

interface JsonWebKeyWithKid extends JsonWebKey {
  // Key Identifier of the JWK
  readonly kid: string;
}

// isValidBrokerRequest authenticates an incoming request to ensure it is
// signed by the provided brokerPublicKeys
//
// It returns true when the incoming request is signed by the corresponding
// private key, with each private key unique to each Pub/Sub broker.
//
// It returns false in all other cases.
export async function isValidBrokerRequest(
  req: Request,
  brokerPublicKeys: string
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

  // Convert base64 encoded
  let signatureBuffer = Uint8Array.from(atob(signature), (c) =>
    c.charCodeAt(0)
  );

  // Deserialize the encoded list of JWKs
  let publicJWKList: Array<JsonWebKeyWithKid> = JSON.parse(
    atob(brokerPublicKeys)
  );

  // Lookup JWK by Key Identifier
  let publicJWK = publicJWKList.find((jwk) => jwk.kid === keyId);

  // No JWK in the Set, request can not be verified
  if (!publicJWK) {
    return false;
  }

  // Import the public key from our Broker (in JWK format) so we can verify the
  // request is from _our_ Broker, and not an untrusted third-party
  let publicKey = await crypto.subtle.importKey("jwk", publicJWK, alg, false, [
    "verify",
  ]);

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

  return false;
}
