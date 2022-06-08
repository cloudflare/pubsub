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

// const testRequest: Request

test("isValidBrokerRequest should return a boolean", async () => {
  let req = new Request("https://broker.namespace.cloudflarepubsub.com");
  let publicKeys = testPublicKeys;
  let isValid = await isValidBrokerRequest(req, publicKeys);
  assert.type(isValid, "boolean")
});

test("should reject a request without a signature", async () => {
  let req = new Request("https://broker.namespace.cloudflarepubsub.com");
  let publicKeys = testPublicKeys;
  let isValid = await isValidBrokerRequest(req, publicKeys);
  assert.not(isValid)
});

test("should reject a request with an invalid signature", async () => {
});

test("should accept a request with a valid signature", async () => {
});

test.run();
