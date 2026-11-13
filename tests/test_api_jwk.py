import json

import pytest

from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
)

from .utils import crypto_required, key_path, no_crypto_required

if has_crypto:
    from jwt.algorithms import ECAlgorithm, HMACAlgorithm, OKPAlgorithm, RSAAlgorithm

# CPython's json scanner aborts with RecursionError once nesting crosses its
# own depth (objects need more levels than arrays). The payload is built by
# string concatenation rather than from nested Python objects, so no Python
# recursion is involved in constructing it — only the scanner's limit is hit.
DEEPLY_NESTED_JSON = '{"x": ' * 5000 + '{"kty": "RSA"}' + "}" * 5000


class TestPyJWK:
    @crypto_required
    def test_should_load_key_from_jwk_data_dict(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_from_jwk_data_json_string(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_json(json.dumps(key_data))

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256
        assert jwk.algorithm_name == "RS256"

    @crypto_required
    def test_should_load_key_from_dict_with_algorithm(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data, algorithm="RS256")

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256
        assert jwk.algorithm_name == "RS256"

    @crypto_required
    def test_should_load_key_ec_p256_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256
        assert jwk.algorithm_name == "ES256"

    @crypto_required
    def test_should_load_key_ec_p384_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-384.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA384
        assert jwk.algorithm_name == "ES384"

    @crypto_required
    def test_should_load_key_ec_p521_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-521.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA512
        assert jwk.algorithm_name == "ES512"

    @crypto_required
    def test_should_load_key_ec_secp256k1_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_secp256k1.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256
        assert jwk.algorithm_name == "ES256K"

    @crypto_required
    def test_should_load_key_hmac_from_dict(self) -> None:
        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256
        assert jwk.algorithm_name == "HS256"

    @crypto_required
    def test_should_load_key_hmac_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        del key_data["alg"]
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256
        assert jwk.algorithm_name == "HS256"

    @crypto_required
    def test_should_load_key_okp_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "OKP"
        assert isinstance(jwk.Algorithm, OKPAlgorithm)
        assert jwk.algorithm_name == "EdDSA"

    @crypto_required
    def test_from_dict_should_throw_exception_if_arg_is_invalid(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_rsa_pub = json.loads(keyfile.read())
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            valid_ec_pub = json.loads(keyfile.read())
        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            valid_okp_pub = json.loads(keyfile.read())

        # Unknown algorithm
        with pytest.raises(PyJWKError):
            PyJWK.from_dict(valid_rsa_pub, algorithm="unknown")

        # Missing kty
        v = valid_rsa_pub.copy()
        del v["kty"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown kty
        v = valid_rsa_pub.copy()
        v["kty"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown EC crv
        v = valid_ec_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown OKP crv
        v = valid_okp_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Missing OKP crv
        v = valid_okp_pub.copy()
        del v["crv"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

    @crypto_required
    @pytest.mark.parametrize("not_an_object", [7, None, ["kty", "RSA"], "RSA"])
    def test_from_dict_rejects_members_that_are_not_json_objects(
        self, not_an_object: object
    ) -> None:
        # A non-dict JWK member must be an InvalidKeyError, never an uncaught
        # AttributeError from .get() on the wrong type.
        with pytest.raises(InvalidKeyError, match="must be a JSON object"):
            PyJWK(not_an_object)  # type: ignore[arg-type]

    @crypto_required
    def test_oct_key_missing_material_raises_invalid_key_error(self) -> None:
        # `k` absent: the stdlib KeyError must not escape the key entry.
        with pytest.raises(InvalidKeyError, match="'k' parameter"):
            PyJWK({"kty": "oct", "kid": "hmac"})

        # `k` present but the wrong JSON type likewise normalizes.
        with pytest.raises(InvalidKeyError, match="'k' parameter"):
            PyJWK({"kty": "oct", "k": 123})

    @crypto_required
    @pytest.mark.parametrize(
        "raw",
        [
            "{not valid json",
            '{"kty": "RSA",',  # truncated
            DEEPLY_NESTED_JSON,  # beyond the json scanner nesting limit
        ],
    )
    def test_from_json_normalizes_bad_payloads(self, raw: str) -> None:
        # Syntax errors, truncation and excessive nesting must all surface as
        # a library InvalidKeyError rather than json.JSONDecodeError or
        # RecursionError.
        with pytest.raises(InvalidKeyError):
            PyJWK.from_json(raw)

    @no_crypto_required
    def test_missing_crypto_library_good_error_message(self) -> None:
        with pytest.raises(PyJWKError) as exc:
            PyJWK({"kty": "dummy"}, algorithm="RS256")
            assert "cryptography" in str(exc.value)

    @no_crypto_required
    def test_missing_crypto_library_raises_missing_cryptography_error(self) -> None:
        with pytest.raises(MissingCryptographyError):
            PyJWK({"kty": "dummy"}, algorithm="RS256")


class TestPyJWKSet:
    @crypto_required
    def test_should_skip_malformed_rsa_key_and_load_remaining_keys(self) -> None:
        with open(key_path("jwk_rsa_key.json")) as keyfile:
            malformed_key = json.loads(keyfile.read())

        malformed_key["d"] = "AAAAAA"
        for parameter in ("p", "q", "dp", "dq", "qi"):
            del malformed_key[parameter]

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_key = json.loads(keyfile.read())

        jwk_set = PyJWKSet.from_dict({"keys": [malformed_key, valid_key]})

        assert len(jwk_set.keys) == 1
        assert jwk_set.keys[0].key_type == "RSA"

    @crypto_required
    def test_should_load_keys_from_jwk_data_dict(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_keys_from_jwk_data_json_string(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_json(json.dumps({"keys": [key_data]}))
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_keyset_should_index_by_kid(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})

        jwk = jwk_set.keys[0]
        assert jwk == jwk_set["keyid-abc123"]

        with pytest.raises(KeyError):
            _ = jwk_set["this-kid-does-not-exist"]

    @crypto_required
    def test_keyset_iterator(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})

        assert jwk_set.keys == [jwk for jwk in jwk_set]

    @crypto_required
    def test_keyset_skips_members_that_are_not_objects(self) -> None:
        # A JWKS member that isn't a JSON object is an unusable key, not a
        # reason to fail the whole set with an uncaught AttributeError.
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data = json.loads(algo.to_jwk(pub_key))
        key_data["alg"] = "RS256"
        key_data["kid"] = "usable"

        keyset = PyJWKSet.from_dict({"keys": [None, "nope", 7, key_data]})

        assert [key.key_id for key in keyset.keys] == ["usable"]

    @crypto_required
    def test_keyset_of_only_non_object_members_raises_set_error(self) -> None:
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [None]})

    @crypto_required
    def test_keyset_skips_members_with_invalid_component_types(self) -> None:
        # RSA components must be strings; a number is unusable and must not
        # surface as an uncaught TypeError.
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [{"kty": "RSA", "n": 1, "e": "AQAB"}]})

    @crypto_required
    def test_jwk_with_invalid_component_type_raises_invalid_key_error(self) -> None:
        with pytest.raises(InvalidKeyError):
            PyJWK({"kty": "RSA", "alg": "RS256", "n": 1, "e": "AQAB"})

    @crypto_required
    def test_valid_member_is_not_penalized_when_another_lacks_material(self) -> None:
        # A member missing key material is skipped; a fully valid member in
        # the same set must remain usable regardless of ordering.
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_key = json.loads(keyfile.read())
        valid_key["kid"] = "usable"
        member_missing_material = {"kty": "oct", "kid": "unusable"}

        for keys in (
            [member_missing_material, valid_key],
            [valid_key, member_missing_material],
        ):
            keyset = PyJWKSet.from_dict({"keys": keys})
            assert [key.key_id for key in keyset.keys] == ["usable"]

    @crypto_required
    @pytest.mark.parametrize(
        "members",
        [
            [{"kty": "oct"}],  # missing key material
            [{"kty": "oct"}, None, 7, "nope"],  # missing material + non-objects
            [None, 7],  # only non-object members
        ],
    )
    def test_set_of_only_unusable_members_raises_set_error(
        self, members: list[object]
    ) -> None:
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": members})

    @crypto_required
    @pytest.mark.parametrize(
        "raw",
        [
            '{"keys": [}',  # invalid syntax
            '{"keys": [',  # truncated
            '{"keys": ' + DEEPLY_NESTED_JSON + "}",  # excessive nesting
        ],
    )
    def test_from_json_normalizes_bad_payloads(self, raw: str) -> None:
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_json(raw)

    @crypto_required
    def test_keyset_with_unknown_alg(self) -> None:
        # first keyset with unusable key and usable key
        with open(key_path("jwk_keyset_with_unknown_alg.json")) as keyfile:
            jwks_text = keyfile.read()
        jwks = json.loads(jwks_text)
        assert len(jwks.get("keys")) == 2
        keyset = PyJWKSet.from_json(jwks_text)
        assert len(keyset.keys) == 1

        # second keyset with only unusable key -> catch exception
        with open(key_path("jwk_keyset_only_unknown_alg.json")) as keyfile:
            jwks_text = keyfile.read()
            jwks = json.loads(jwks_text)
            assert len(jwks.get("keys")) == 1
            with pytest.raises(PyJWKSetError):
                _ = PyJWKSet.from_json(jwks_text)

    @crypto_required
    def test_invalid_keys_list(self) -> None:
        with pytest.raises(PyJWKSetError) as err:
            PyJWKSet(keys="string")  # type: ignore[arg-type]
        assert str(err.value) == "Invalid JWK Set value"

    @crypto_required
    def test_empty_keys_list(self) -> None:
        with pytest.raises(PyJWKSetError) as err:
            PyJWKSet(keys=[])
        assert str(err.value) == "The JWK Set did not contain any keys"

    @no_crypto_required
    def test_missing_crypto_library_raises_when_required(self) -> None:
        with pytest.raises(MissingCryptographyError):
            PyJWKSet(keys=[{"kty": "RSA"}])
