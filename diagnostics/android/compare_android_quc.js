"use strict";

/*
 * Build a synthetic QUC request inside the Android process without invoking
 * UserCenterRpc, HttpPostRequest, or any other network-capable class.
 */
Java.perform(function () {
    const PREFIX = "[quc-compare] ";
    const COMMON_VALUE_KEYS = [
        "device_lang", "app", "device_os", "format", "from",
        "mSystemVersion", "method", "mname", "oaid", "os_board",
        "os_manufacturer", "os_model", "os_sdk_version", "quc_lang",
        "quc_sdk_version", "res_mode", "sdpi", "sh", "sw", "ua",
        "ui_ver", "v",
    ];
    const SYNTHETIC_IDS = {
        androidid: "0123456789abcdef",
        mid: "0123456789abcdef0123456789abcdef",
        oaid: "dummy-oaid",
        qh_id: "dummy-qh-id",
        vt_guid: "1700000000000",
    };
    const DUMMY_DES_KEY = "DESkey8!";
    const DUMMY_FULL_KEY = "A".repeat(109) + DUMMY_DES_KEY;
    const ANDROID_SIGNATURE_SUFFIX = "i7v2m5x6q";

    function emit(event, details) {
        try {
            console.log(PREFIX + JSON.stringify(
                Object.assign({ event: event }, details || {})
            ));
        } catch (error) {
            console.log(PREFIX +
                "{\"event\":\"error\",\"stage\":\"emit\",\"reason\":\"serialization_failed\"}");
        }
    }

    function fail(stage, reason) {
        emit("error", { stage: stage, reason: reason });
    }

    function stringValue(value) {
        return value === null || value === undefined ? null : String(value);
    }

    function byteHex(bytes) {
        let output = "";
        for (let index = 0; index < bytes.length; index += 1) {
            const value = bytes[index] & 0xff;
            output += (value < 16 ? "0" : "") + value.toString(16);
        }
        return output;
    }

    function digestHex(MessageDigest, bytes) {
        return byteHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    function byteArray(bytes, offset, length) {
        const result = [];
        const start = offset === undefined ? 0 : offset;
        const end = length === undefined ? bytes.length : start + length;
        for (let index = start; index < end; index += 1) {
            result.push(bytes[index] & 0xff);
        }
        return result;
    }

    function javaBytes(values) {
        return Java.array("byte", values.map(function (value) {
            return value > 127 ? value - 256 : value;
        }));
    }

    function md5Hex(MessageDigest, JString, value) {
        return byteHex(
            MessageDigest.getInstance("MD5").digest(
                JString.$new(value).getBytes("UTF-8")
            )
        );
    }

    function mapKeys(map) {
        const result = [];
        const iterator = map.keySet().iterator();
        while (iterator.hasNext()) {
            result.push(String(iterator.next()));
        }
        return result;
    }

    function setFinalString(target, fieldName, value, JString) {
        const field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, JString.$new(value));
    }

    function seedLoginMap(HashMap, MessageDigest, JString, includeIds) {
        const map = HashMap.$new();
        map.put("fields", "qid,username,nickname,loginemail,head_pic,mobile");
        map.put("head_type", "q");
        map.put("is_keep_alive", "1");
        map.put("loginType", "801");
        map.put("needDeviceCheck", "1");
        map.put("password", md5Hex(
            MessageDigest, JString, "dummy-password"
        ));
        map.put("sec_type", "bool");
        map.put("trace_id", "src_and_1916_1700000000000");
        map.put("username", "dummy@example.invalid");
        if (includeIds) {
            Object.keys(SYNTHETIC_IDS).forEach(function (key) {
                map.put(key, SYNTHETIC_IDS[key]);
            });
        }
        return map;
    }

    function identityMetadata(map, expectedSynthetic) {
        const metadata = {};
        let synthetic = true;
        Object.keys(SYNTHETIC_IDS).forEach(function (key) {
            const value = map.get(key);
            const text = stringValue(value);
            const matches = text === SYNTHETIC_IDS[key];
            metadata[key] = {
                type: value === null ? "null" : String(value.getClass().getName()),
                length: text === null ? null : text.length,
            };
            if (expectedSynthetic) {
                metadata[key].synthetic = matches;
                synthetic = synthetic && matches;
            }
        });
        return { values: metadata, all_synthetic: synthetic };
    }

    function commonValues(map) {
        const values = {};
        COMMON_VALUE_KEYS.forEach(function (key) {
            values[key] = stringValue(map.get(key));
        });
        return values;
    }

    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const AndroidBase64 = Java.use("android.util.Base64");
        const BasicParamsTools = Java.use(
            "com.qihoo360.accounts.api.auth.p.BasicParamsTools"
        );
        const ClientAuthKey = Java.use(
            "com.qihoo360.accounts.api.auth.p.ClientAuthKey"
        );
        const Cipher = Java.use("javax.crypto.Cipher");
        const HashMap = Java.use("java.util.HashMap");
        const JString = Java.use("java.lang.String");
        const LinkedHashMap = Java.use("java.util.LinkedHashMap");
        const MessageDigest = Java.use("java.security.MessageDigest");
        const SettingsGlobal = Java.use("android.provider.Settings$Global");
        const System = Java.use("java.lang.System");
        const URLEncodedUtils = Java.use(
            "com.qihoo360.accounts.api.util.URLEncodedUtils"
        );

        const cipherStates = Object.create(null);
        let syntheticCipherProbe = false;
        let desStageReported = false;

        function cipherId(cipher) {
            return String(System.identityHashCode(cipher));
        }

        function stateFor(cipher) {
            const id = cipherId(cipher);
            cipherStates[id] = cipherStates[id] || {
                transformation: null,
                mode: null,
                key: null,
                iv: null,
            };
            return cipherStates[id];
        }

        function reportDesStage(cipher, finalInput, output) {
            if (!syntheticCipherProbe || desStageReported) {
                return;
            }
            const state = stateFor(cipher);
            const transformation = state.transformation || "";
            if (!/DES/i.test(transformation) || state.mode !== 1) {
                return;
            }
            const plaintext = finalInput === null ? [] : finalInput;
            const expectedKey = byteArray(
                JString.$new(DUMMY_DES_KEY).getBytes("UTF-8")
            );
            if (JSON.stringify(state.key) !== JSON.stringify(expectedKey)) {
                fail("des_stage", "fixed_des_key_not_verified");
                return;
            }
            const cipherBytes = byteArray(output);
            const plaintextBytes = javaBytes(plaintext);
            const cipherJavaBytes = javaBytes(cipherBytes);
            desStageReported = true;
            emit("des_stage", {
                transformation: transformation,
                key_ascii: DUMMY_DES_KEY,
                key_hex: byteHex(state.key),
                iv_hex: state.iv === null ? null : byteHex(state.iv),
                plaintext: String(JString.$new(plaintextBytes, "UTF-8")),
                plaintext_length: plaintext.length,
                plaintext_sha256: digestHex(MessageDigest, plaintextBytes),
                plaintext_hex: byteHex(plaintext),
                plaintext_base64: String(AndroidBase64.encodeToString(
                    plaintextBytes, 2
                )),
                cipher_length: cipherBytes.length,
                cipher_sha256: digestHex(MessageDigest, cipherJavaBytes),
                cipher_hex: byteHex(cipherBytes),
                cipher_base64_padded: String(AndroidBase64.encodeToString(
                    cipherJavaBytes, 2
                )),
                cipher_base64_unpadded: String(AndroidBase64.encodeToString(
                    cipherJavaBytes, 3
                )),
                synthetic: true,
            });
        }

        function installCipherHooks() {
            const hooks = [];
            const getInstance = Cipher.getInstance.overload("java.lang.String");
            getInstance.implementation = function (transformation) {
                const result = getInstance.call(this, transformation);
                stateFor(result).transformation = String(transformation);
                return result;
            };
            hooks.push(getInstance);

            [
                ["int", "java.security.Key"],
                ["int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec"],
                ["int", "java.security.Key", "java.security.AlgorithmParameters"],
            ].forEach(function (types) {
                try {
                    const init = Cipher.init.overload.apply(Cipher.init, types);
                    init.implementation = function () {
                        const result = init.apply(this, arguments);
                        const state = stateFor(this);
                        state.mode = Number(arguments[0]);
                        try {
                            state.key = byteArray(arguments[1].getEncoded());
                        } catch (error) {
                            state.key = null;
                        }
                        try {
                            const iv = this.getIV();
                            state.iv = iv === null ? null : byteArray(iv);
                        } catch (error) {
                            state.iv = null;
                        }
                        return result;
                    };
                    hooks.push(init);
                } catch (error) {
                    // This Android release does not expose that overload.
                }
            });

            const doFinal = Cipher.doFinal.overload("[B");
            doFinal.implementation = function (input) {
                const result = doFinal.call(this, input);
                reportDesStage(this, byteArray(input), result);
                return result;
            };
            hooks.push(doFinal);

            const doFinalRange = Cipher.doFinal.overload("[B", "int", "int");
            doFinalRange.implementation = function (input, offset, length) {
                const result = doFinalRange.call(this, input, offset, length);
                reportDesStage(
                    this,
                    byteArray(input, Number(offset), Number(length)),
                    result
                );
                return result;
            };
            hooks.push(doFinalRange);

            return function () {
                hooks.forEach(function (hook) {
                    hook.implementation = null;
                });
            };
        }

        const application = ActivityThread.currentApplication();
        if (application === null) {
            fail("setup", "application_unavailable");
            return;
        }
        const airplaneMode = SettingsGlobal.getInt(
            application.getContentResolver(), "airplane_mode_on", 0
        );
        if (airplaneMode !== 1) {
            fail("setup", "airplane_mode_required");
            return;
        }
        emit("offline_guard", { airplane_mode: true });

        const clientAuth = ClientAuthKey.getInstance();
        const tools = BasicParamsTools.$new(clientAuth);
        const generatedKey = String(tools.mCryptKeyFull.value);
        emit("random_key", {
            length: generatedKey.length,
            ascii_alphanumeric: /^[A-Za-z0-9]+$/.test(generatedKey),
            has_uppercase: /[A-Z]/.test(generatedKey),
            has_lowercase: /[a-z]/.test(generatedKey),
            has_digit: /[0-9]/.test(generatedKey),
            sample_disclosed: false,
        });

        try {
            const generateRandom = BasicParamsTools.a.overload("int");
            const randomSample = String(generateRandom.call(tools, 65536));
            const observedCodes = Object.create(null);
            for (let index = 0; index < randomSample.length; index += 1) {
                observedCodes[randomSample.charCodeAt(index)] = true;
            }
            const codePoints = Object.keys(observedCodes)
                .map(function (value) { return parseInt(value, 10); })
                .sort(function (left, right) { return left - right; });
            const observedCharacters = codePoints.map(function (value) {
                return String.fromCharCode(value);
            }).join("");
            emit("random_charset", {
                sample_length: randomSample.length,
                observed_size: codePoints.length,
                observed_code_points: codePoints,
                observed_characters: observedCharacters,
                sha256: digestHex(
                    MessageDigest,
                    JString.$new(observedCharacters).getBytes("UTF-8")
                ),
                generated_sample_disclosed: false,
            });
        } catch (error) {
            emit("random_charset", {
                status: "UNKNOWN",
                reason: "native_generator_call_failed",
            });
        }

        const runtimeParams = seedLoginMap(
            HashMap, MessageDigest, JString, false
        );
        tools.buildCommonParams(
            application.getApplicationContext(),
            "UserIntf.login",
            runtimeParams
        );
        emit("runtime_identity_metadata", identityMetadata(
            runtimeParams, false
        ).values);
        emit("common_values", { values: commonValues(runtimeParams) });

        const params = seedLoginMap(HashMap, MessageDigest, JString, true);

        const targetMapId = String(System.identityHashCode(params));
        const put = HashMap.put.overload(
            "java.lang.Object", "java.lang.Object"
        );
        put.implementation = function (key, value) {
            const keyText = String(key);
            if (String(System.identityHashCode(this)) === targetMapId &&
                    Object.prototype.hasOwnProperty.call(
                        SYNTHETIC_IDS, keyText
                    )) {
                return put.call(this, key, JString.$new(SYNTHETIC_IDS[keyText]));
            }
            return put.call(this, key, value);
        };

        try {
            tools.buildCommonParams(
                application.getApplicationContext(),
                "UserIntf.login",
                params
            );
        } finally {
            put.implementation = null;
        }

        const syntheticMetadata = identityMetadata(params, true);
        emit("synthetic_identity_metadata", syntheticMetadata.values);
        emit("synthetic_common_values", { values: commonValues(params) });

        if (!syntheticMetadata.all_synthetic) {
            fail("synthetic_ids", "replacement_not_verified");
            return;
        }

        const signature = stringValue(params.get("sig"));
        if (signature === null || !/^[a-fA-F0-9]{32}$/.test(signature)) {
            fail("signature", "native_signature_unavailable");
            return;
        }
        emit("dummy_signature", {
            value: signature.toLowerCase(),
            input_names: mapKeys(params).filter(function (key) {
                return key !== "sig";
            }).sort(),
        });
        const signatureNames = mapKeys(params).filter(function (key) {
            return key !== "sig";
        }).sort();
        const signatureInput = signatureNames.map(function (key) {
            return key + "=" + String(params.get(key));
        }).join("") + ANDROID_SIGNATURE_SUFFIX;
        const signatureBytes = JString.$new(signatureInput).getBytes("UTF-8");
        emit("dummy_signature_input", {
            sha256: digestHex(MessageDigest, signatureBytes),
            utf8_length: signatureBytes.length,
            parameter_count: signatureNames.length,
            input_names: signatureNames,
            calculated_md5: byteHex(
                MessageDigest.getInstance("MD5").digest(signatureBytes)
            ),
            matches_native: byteHex(
                MessageDigest.getInstance("MD5").digest(signatureBytes)
            ) === signature.toLowerCase(),
            canonical_input_disclosed: false,
        });

        let fixedKeyInstalled = false;
        try {
            setFinalString(tools, "mCryptKeyFull", DUMMY_FULL_KEY, JString);
            setFinalString(
                tools,
                "mCryptKey",
                DUMMY_FULL_KEY.substring(DUMMY_FULL_KEY.length - 8),
                JString
            );
            fixedKeyInstalled = (
                String(tools.mCryptKeyFull.value) === DUMMY_FULL_KEY &&
                String(tools.mCryptKey.value) ===
                    DUMMY_FULL_KEY.substring(DUMMY_FULL_KEY.length - 8)
            );
        } catch (error) {
            fixedKeyInstalled = false;
        }

        if (fixedKeyInstalled) {
            const iterationOrder = mapKeys(params);
            const removeCipherHooks = installCipherHooks();
            syntheticCipherProbe = true;
            let envelope;
            try {
                envelope = tools.getCryptedParams(params);
            } finally {
                syntheticCipherProbe = false;
                removeCipherHooks();
            }
            const parad = stringValue(envelope.get("parad"));
            const key = stringValue(envelope.get("key"));
            if (parad === null || key === null) {
                fail("dummy_envelope", "native_envelope_incomplete");
            } else {
                const cipherBytes = AndroidBase64.decode(parad, 3);
                emit("dummy_envelope", {
                    fixed_key_installed: true,
                    input_iteration_order: iterationOrder,
                    output_names: mapKeys(envelope).sort(),
                    key_length: key.length,
                    key_has_padding: /=+$/.test(key),
                    parad_length: parad.length,
                    parad_has_padding: /=+$/.test(parad),
                    parad_cipher_length: cipherBytes.length,
                    parad_cipher_sha256: digestHex(
                        MessageDigest, cipherBytes
                    ),
                    envelope_values_disclosed: false,
                });
            }
            if (!desStageReported) {
                emit("des_stage", {
                    status: "UNKNOWN",
                    reason: "java_cipher_boundary_not_observed",
                    synthetic: true,
                });
            }
        } else {
            emit("dummy_envelope", {
                fixed_key_installed: false,
                status: "UNKNOWN",
                reason: "final_key_fields_not_replaceable",
                envelope_values_disclosed: false,
            });
        }

        const form = LinkedHashMap.$new();
        form.put("space", "a b");
        form.put("plus", "a+b");
        form.put("slash", "a/b");
        form.put("equals", "a=b");
        form.put("percent", "a%b");
        form.put("unicode", "Gr\u00fc\u00dfe");
        emit("form_encoding", {
            charset: "UTF-8",
            field_order: mapKeys(form),
            body: String(URLEncodedUtils.format(form, "UTF-8")),
        });

        emit("complete", {
            network_classes_used: false,
            http_request_sent: false,
        });
    } catch (error) {
        fail("runtime", "safe_probe_failed");
    }
});
