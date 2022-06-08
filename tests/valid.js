import { test } from "uvu";
import * as assert from "uvu/assert";
import { isValidBrokerRequest } from "../dist/index.js";

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

const testRequest = new Request("https://broker.namespace.cloudflarepubsub.com");

test("isValidBrokerRequest should return a boolean", async () => {
  let req = new Request("https://broker.namespace.cloudflarepubsub.com");
  let publicKeys = testPublicKeys;
  let isValid = await isValidBrokerRequest(testRequest, publicKeys);
  assert.type(isValid, "boolean")
});

test("should reject a reject when the publicKeys are empty", async () => {
  let emptyKeys = ""
  let isValid = await isValidBrokerRequest(testRequest, emptyKeys);
  assert.not(isValid)
});

test("should reject a reject when the publicKeys are invalid", async () => {
  let invalidKeys = "some invalid string"
  let isValid = await isValidBrokerRequest(testRequest, invalidKeys);
  assert.not(isValid)
});

test("should reject a request with an invalid signature", async () => {
  // TODO
});

test("should accept a request with a valid signature", async () => {
  // TODO
});

test.run();
