// Copyright (c) 2022 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

import { test } from "uvu";
import * as assert from "uvu/assert";
import { isValidBrokerRequest } from "../src";

const testPublicKeys = `{
    "keys": [
      {
        "use": "sig",
        "kty": "OKP",
        "kid": "JDPuYJqHOvqzlakkNFQ9kfN7WsYs5uHndp_ziRdmOCU",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "Phf82R8tG1FdY475-AgtlaWIwH1lLFlfWu5LrsKhyjw"
      },
      {
        "use": "sig",
        "kty": "OKP",
        "kid": "qk7Z4hbN738v-m2CKdVaKTav9pU32MAaQXB2tDaQ-_o",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "Bt4kQWcK_XhZP1ZxEflsoYbqaBm9rEDk_jNWPdhxwTI"
      }
    ]
  }`;

const testRequest = new Request(
	"https://broker.namespace.cloudflarepubsub.com"
);

test("isValidBrokerRequest should return a boolean", async () => {
	let req = new Request("https://broker.namespace.cloudflarepubsub.com");
	let publicKeys = testPublicKeys;
	let isValid = await isValidBrokerRequest(testRequest, publicKeys);
	assert.type(isValid, "boolean");
});

test("should reject a reject when the publicKeys are empty", async () => {
	let emptyKeys = "";
	let isValid = await isValidBrokerRequest(testRequest, emptyKeys);
	assert.not(isValid);
});

test("should reject a reject when the publicKeys are invalid", async () => {
	let invalidKeys = "some invalid string";
	let isValid = await isValidBrokerRequest(testRequest, invalidKeys);
	assert.not(isValid);
});

test("should reject a request with a missing signature", async () => {
	let missingSigRequest = new Request(
		"https://broker.namespace.cloudflarepubsub.com",
		{
			headers: {
				"X-Signature-Timestamp": "1654703935",
				"X-Signature-Key-Id": "JDPuYJqHOvqzlakkNFQ9kfN7WsYs5uHndp_ziRdmOCU",
			},
		}
	);
	let isValid = await isValidBrokerRequest(missingSigRequest, testPublicKeys);
	assert.not(isValid);
});

test("should reject a request with a missing timestamp", async () => {
	let missingSigRequest = new Request(
		"https://broker.namespace.cloudflarepubsub.com",
		{
			headers: {
				"X-Signature-Ed25519":
					"lMfYlzUJXx2u5NGSSS2Y5+L0gRO12UplI/m7IKWgCWKHdaOWbmFyD/04UHBzJZE/TxXDJa1FSu8X3K5/YT+PBA==",
				"X-Signature-Key-Id": "JDPuYJqHOvqzlakkNFQ9kfN7WsYs5uHndp_ziRdmOCU",
			},
		}
	);
	let isValid = await isValidBrokerRequest(missingSigRequest, testPublicKeys);
	assert.not(isValid);
});

test("should reject a request with a missing key ID", async () => {
	let missingSigRequest = new Request(
		"https://broker.namespace.cloudflarepubsub.com",
		{
			headers: {
				"X-Signature-Ed25519":
					"lMfYlzUJXx2u5NGSSS2Y5+L0gRO12UplI/m7IKWgCWKHdaOWbmFyD/04UHBzJZE/TxXDJa1FSu8X3K5/YT+PBA==",
				"X-Signature-Timestamp": "1654703935",
			},
		}
	);
	let isValid = await isValidBrokerRequest(missingSigRequest, testPublicKeys);
	assert.not(isValid);
});

test.run();
