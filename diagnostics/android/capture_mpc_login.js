"use strict";

/* Passive metadata capture for one manually initiated MPC QUC login. */
Java.perform(function () {
    const TARGET_HOST = "passport.360.cn";
    const TARGET_PATH = "/request.php";
    const TARGET_FROM = "mpc_smarthome_and";
    const System = Java.use("java.lang.System");
    const MessageDigest = Java.use("java.security.MessageDigest");
    const AndroidBase64 = Java.use("android.util.Base64");

    const calledHooks = Object.create(null);
    const rpcCandidates = Object.create(null);
    const rpcToBasic = Object.create(null);
    const trackedBasic = Object.create(null);
    const trackedRequests = Object.create(null);
    const rsaDefaults = Object.create(null);
    const safeValues = Object.create(null);

    let buildingRpc = false;
    let pendingBasicId = null;
    let activeRpcId = null;
    let captureStarted = false;
    let captureComplete = false;
    let capturedPlainParams = null;
    let commonBefore = [];
    let capturedHost = null;
    let capturedPath = null;
    let innerReported = false;
    let commonReported = false;
    let uriReported = false;
    let outerReported = false;
    let rsaReported = false;
    let networkReported = false;
    let clientFromReported = false;
    let initializeReported = false;

    function emit(event, details) {
        try {
            const line = JSON.stringify(Object.assign({ event: event }, details || {}));
            console.log("[mpc-capture] " + line);
            return true;
        } catch (error) {
            console.log("[mpc-capture] {\"event\":\"capture_debug\",\"stage\":\"emit\",\"reason\":\"serialization_failed\"}");
            return false;
        }
    }

    function debug(stage, reason) {
        emit("capture_debug", { stage: stage, reason: reason });
    }

    function objectId(value) {
        return String(System.identityHashCode(value));
    }

    function normalizedKey(value) {
        return String(value).replace(/[^A-Za-z0-9]/g, "").toLowerCase();
    }

    function sanitizedKey(value) {
        const key = String(value);
        return /^[A-Za-z0-9_.-]{1,80}$/.test(key)
            ? key
            : "<nonstandard-key:length=" + key.length + ">";
    }

    function safeProfileValue(value) {
        const text = value === null ? "" : String(value);
        return /^[A-Za-z0-9_.-]{1,80}$/.test(text) ? text : null;
    }

    function snapshotKeys(map, stage) {
        const found = Object.create(null);
        if (map === null || map === undefined) {
            debug(stage, "map_missing");
            return [];
        }
        try {
            const keys = map.keySet().toArray();
            for (let index = 0; index < keys.length; index += 1) {
                found[sanitizedKey(keys[index])] = true;
            }
        } catch (error) {
            debug(stage, "key_iteration_failed");
        }
        return Object.keys(found).sort();
    }

    function rememberSafeMetadata(target, keyValue, valueValue) {
        const normalized = normalizedKey(keyValue);
        const value = valueValue === null ? "" : String(valueValue);
        if (normalized === "logintype" && /^-?[0-9]{1,10}$/.test(value)) {
            target.loginType = value;
        } else if (normalized === "needdevicecheck" &&
                   /^(?:0|1|true|false)$/i.test(value)) {
            target.needDeviceCheck = value;
        } else if (normalized === "captchatype" &&
                   /^[A-Za-z0-9_-]{1,32}$/.test(value)) {
            target.captchaType = value;
        } else if (normalized === "from") {
            const safeFrom = safeProfileValue(value);
            if (safeFrom !== null) {
                target.from = safeFrom;
            }
        }
    }

    function inspectSafeMapValues(map, target, stage) {
        if (map === null || map === undefined) {
            debug(stage, "map_missing");
            return;
        }
        try {
            const keys = map.keySet().toArray();
            for (let index = 0; index < keys.length; index += 1) {
                rememberSafeMetadata(target, keys[index], map.get(keys[index]));
            }
        } catch (error) {
            debug(stage, "safe_value_inspection_failed");
        }
    }

    function hookCalled(hook, overload) {
        const id = hook + "(" + overload + ")";
        if (!calledHooks[id]) {
            calledHooks[id] = true;
            emit("hook_called", { hook: hook, overload: overload });
        }
    }

    function activate(reason, rpcId) {
        if (!captureStarted) {
            captureStarted = true;
            emit("capture_activated", { reason: reason });
        }
        if (rpcId !== null && rpcId !== undefined) {
            activeRpcId = rpcId;
            if (rpcToBasic[rpcId] !== undefined) {
                trackedBasic[rpcToBasic[rpcId]] = true;
            }
        }
    }

    function maybeActivateRpc(rpcId) {
        const candidate = rpcCandidates[rpcId];
        if (candidate === undefined) {
            return;
        }
        if (candidate.normalized.username && candidate.normalized.password &&
            candidate.normalized.logintype) {
            activate("login_parameter_names", rpcId);
            Object.assign(safeValues, candidate.safeValues);
        }
    }

    function reportInner() {
        if (innerReported || activeRpcId === null) {
            return;
        }
        const candidate = rpcCandidates[activeRpcId];
        if (candidate === undefined) {
            debug("inner_params", "active_rpc_missing");
            return;
        }
        Object.assign(safeValues, candidate.safeValues);
        innerReported = emit("inner_params", {
            names: Object.keys(candidate.keys).sort(),
            safe_values: Object.assign({}, safeValues),
        });
    }

    function maybeComplete() {
        if (captureComplete || !innerReported || !uriReported ||
            !outerReported || !networkReported) {
            return;
        }
        captureComplete = true;
        emit("capture_complete", {
            have: {
                inner_params: innerReported,
                common_params: commonReported,
                request_uri: uriReported,
                rsa_key: rsaReported,
                outer_params: outerReported,
                http_request: networkReported,
                client_auth_from: clientFromReported,
            },
        });
    }

    function byteHex(bytes) {
        let output = "";
        for (let index = 0; index < bytes.length; index += 1) {
            const value = bytes[index] & 0xff;
            output += (value < 16 ? "0" : "") + value.toString(16);
        }
        return output;
    }

    function rsaFingerprint(publicKey) {
        if (publicKey === null) {
            return null;
        }
        const normalized = String(publicKey)
            .replace(/-----BEGIN [^-]+-----/g, "")
            .replace(/-----END [^-]+-----/g, "")
            .replace(/\s+/g, "");
        if (normalized.length === 0) {
            return null;
        }
        const der = AndroidBase64.decode(normalized, 0);
        return byteHex(MessageDigest.getInstance("SHA-256").digest(der));
    }

    function reportRsa(manager) {
        if (rsaReported || manager === null) {
            return;
        }
        try {
            const id = objectId(manager);
            const activeKey = manager.getRsaPubKey();
            const fingerprint = rsaFingerprint(activeKey);
            if (fingerprint === null) {
                debug("rsa_key", "fingerprint_unavailable");
                return;
            }
            rsaReported = emit("rsa_key", {
                source: rsaDefaults[id] === String(activeKey)
                    ? "default"
                    : "preferences",
                sha256: fingerprint,
            });
            maybeComplete();
        } catch (error) {
            debug("rsa_key", "inspection_failed");
        }
    }

    function reportCommon(params, before, overload) {
        if (commonReported) {
            return;
        }
        const after = snapshotKeys(params, "common_params_after");
        const effectiveBefore = before.length > 0
            ? before
            : activeRpcId !== null && rpcCandidates[activeRpcId] !== undefined
                ? Object.keys(rpcCandidates[activeRpcId].keys).sort()
                : [];
        const beforeSet = Object.create(null);
        effectiveBefore.forEach(function (key) { beforeSet[key] = true; });
        inspectSafeMapValues(params, safeValues, "common_params_values");
        commonReported = emit("common_params", {
            overload: overload,
            before: effectiveBefore,
            after: after,
            added: after.filter(function (key) { return !beforeSet[key]; }),
            from_present: after.some(function (key) {
                return normalizedKey(key) === "from";
            }),
            safe_values: Object.assign({}, safeValues),
        });
        maybeComplete();
    }

    function reportOuter(params, overload) {
        if (outerReported) {
            return;
        }
        const names = snapshotKeys(params, "outer_params_names");
        const lengths = { key: null, parad: null };
        const outerSafe = {};
        let sigOutside = names.some(function (key) {
            return normalizedKey(key) === "sig";
        });
        if (params !== null && params !== undefined) {
            try {
                const keys = params.keySet().toArray();
                for (let index = 0; index < keys.length; index += 1) {
                    const mapKey = keys[index];
                    const key = normalizedKey(mapKey);
                    if (key === "key" || key === "parad") {
                        const value = params.get(mapKey);
                        lengths[key] = value === null ? 0 : String(value).length;
                    } else if (key === "from") {
                        const safeFrom = safeProfileValue(params.get(mapKey));
                        if (safeFrom !== null) {
                            outerSafe.from = safeFrom;
                        }
                    } else if (key === "sig") {
                        sigOutside = true;
                    }
                }
            } catch (error) {
                debug("outer_params", "value_inspection_failed");
            }
        }
        outerReported = emit("outer_params", {
            overload: overload,
            names: names,
            lengths: lengths,
            key_present: names.some(function (key) { return normalizedKey(key) === "key"; }),
            parad_present: names.some(function (key) { return normalizedKey(key) === "parad"; }),
            from_present: names.some(function (key) {
                return normalizedKey(key) === "from";
            }),
            sig_outside: sigOutside,
            safe_values: outerSafe,
        });
        maybeComplete();
    }

    function install(name, callback) {
        try {
            callback();
            emit("hook_installed", { hook: name });
        } catch (error) {
            emit("hook_error", { hook: name, status: "installation_failed" });
        }
    }

    try {
        Java.deoptimizeEverything();
        emit("runtime_ready", { deoptimized: true });
    } catch (error) {
        emit("runtime_ready", { deoptimized: false });
    }

    install("Login.login overloads", function () {
        const Login = Java.use("com.qihoo360.accounts.api.auth.Login");
        Login.login.overloads.forEach(function (overload) {
            const signature = overload.argumentTypes.map(function (type) {
                return type.className;
            }).join(",");
            overload.implementation = function () {
                hookCalled("Login.login", signature);
                return overload.apply(this, arguments);
            };
        });
    });

    install("ClientAuthKey", function () {
        const Client = Java.use(
            "com.qihoo360.accounts.api.auth.p.ClientAuthKey"
        );
        const getFrom = Client.getFrom.overload();
        getFrom.implementation = function () {
            const result = getFrom.call(this);
            const safe = safeProfileValue(result);
            if (!clientFromReported && safe !== null && /smarthome_and$/.test(safe)) {
                clientFromReported = emit("client_auth_from", {
                    source: "getFrom",
                    value: safe,
                });
                maybeComplete();
            }
            return result;
        };

        Client.initialize.overloads.forEach(function (overload) {
            const signature = overload.argumentTypes.map(function (type) {
                return type.className;
            }).join(",");
            overload.implementation = function () {
                if (!initializeReported && arguments.length >= 2) {
                    const configured = safeProfileValue(arguments[1]);
                    if (configured !== null) {
                        initializeReported = emit("client_auth_initialize", {
                            overload: signature,
                            configured_from: configured,
                        });
                    }
                }
                return overload.apply(this, arguments);
            };
        });
    });

    install("UserCenterRpc", function () {
        const Rpc = Java.use("com.qihoo360.accounts.api.auth.p.UserCenterRpc");
        const constructor = Rpc.$init.overload(
            "android.content.Context",
            "com.qihoo360.accounts.api.auth.p.ClientAuthKey",
            "java.lang.String"
        );
        constructor.implementation = function (context, authKey, method) {
            buildingRpc = true;
            pendingBasicId = null;
            try {
                return constructor.call(this, context, authKey, method);
            } finally {
                const rpcId = objectId(this);
                rpcCandidates[rpcId] = rpcCandidates[rpcId] || {
                    keys: Object.create(null),
                    normalized: Object.create(null),
                    safeValues: Object.create(null),
                };
                if (pendingBasicId !== null) {
                    rpcToBasic[rpcId] = pendingBasicId;
                }
                pendingBasicId = null;
                buildingRpc = false;
            }
        };

        const params = Rpc.params.overload(
            "java.lang.String", "java.lang.String"
        );
        params.implementation = function (key, value) {
            const rpcId = objectId(this);
            const candidate = rpcCandidates[rpcId] || {
                keys: Object.create(null),
                normalized: Object.create(null),
                safeValues: Object.create(null),
            };
            rpcCandidates[rpcId] = candidate;
            candidate.keys[sanitizedKey(key)] = true;
            candidate.normalized[normalizedKey(key)] = true;
            rememberSafeMetadata(candidate.safeValues, key, value);
            maybeActivateRpc(rpcId);
            if (activeRpcId === rpcId) {
                hookCalled("UserCenterRpc.params", "java.lang.String,java.lang.String");
            }
            return params.call(this, key, value);
        };

        const copyParams = Rpc.a.overload("java.util.Map");
        copyParams.implementation = function (paramsMap) {
            const rpcId = objectId(this);
            const tracked = activeRpcId === rpcId;
            if (tracked) {
                hookCalled("UserCenterRpc.a", "java.util.Map");
            }
            const result = copyParams.call(this, paramsMap);
            if (tracked) {
                capturedPlainParams = paramsMap;
                commonBefore = snapshotKeys(paramsMap, "rpc_plain_params");
            }
            return result;
        };
    });

    install("AbsHttpPostHelper.getCryptedParams", function () {
        const Helper = Java.use(
            "com.qihoo360.accounts.api.auth.p.AbsHttpPostHelper"
        );
        const getCrypted = Helper.getCryptedParams.overload();
        getCrypted.implementation = function () {
            const relevant = captureStarted &&
                (activeRpcId === objectId(this) ||
                 (capturedHost === TARGET_HOST && capturedPath === TARGET_PATH));
            if (relevant) {
                hookCalled("AbsHttpPostHelper.getCryptedParams", "");
                reportInner();
            }
            const result = getCrypted.call(this);
            if (relevant) {
                reportCommon(capturedPlainParams, commonBefore, "AbsHttpPostHelper fallback");
                emit("crypted_transition", {
                    input_names: snapshotKeys(capturedPlainParams, "crypted_transition_input"),
                    output_names: snapshotKeys(result, "crypted_transition_output"),
                    safe_values: Object.prototype.hasOwnProperty.call(safeValues, "from")
                        ? { from: safeValues.from }
                        : {},
                });
                reportOuter(result, "AbsHttpPostHelper.getCryptedParams()");
            }
            return result;
        };
    });

    install("BasicParamsTools", function () {
        const Tools = Java.use(
            "com.qihoo360.accounts.api.auth.p.BasicParamsTools"
        );
        const constructor = Tools.$init.overload(
            "com.qihoo360.accounts.api.auth.p.ClientAuthKey"
        );
        constructor.implementation = function (authKey) {
            const result = constructor.call(this, authKey);
            const basicId = objectId(this);
            if (buildingRpc) {
                pendingBasicId = basicId;
            }
            try {
                const manager = this.mRsaManager.value;
                rsaDefaults[objectId(manager)] = String(manager.getRsaPubKey());
            } catch (error) {
                debug("rsa_default", "inspection_failed");
            }
            return result;
        };

        const buildCommon = Tools.buildCommonParams.overload(
            "android.content.Context", "java.lang.String", "java.util.Map"
        );
        buildCommon.implementation = function (context, method, params) {
            const relevant = captureStarted &&
                (trackedBasic[objectId(this)] ||
                 (capturedHost === TARGET_HOST && capturedPath === TARGET_PATH));
            if (!relevant) {
                return buildCommon.call(this, context, method, params);
            }
            hookCalled(
                "BasicParamsTools.buildCommonParams",
                "android.content.Context,java.lang.String,java.util.Map"
            );
            capturedPlainParams = params;
            commonBefore = snapshotKeys(params, "common_params_before");
            const result = buildCommon.call(this, context, method, params);
            reportCommon(
                params,
                commonBefore,
                "android.content.Context,java.lang.String,java.util.Map"
            );
            return result;
        };

        function observeUri(tools, uri, overload) {
            if (uri === null) {
                debug("request_uri", "uri_missing");
                return;
            }
            const host = String(uri.getHost());
            const path = String(uri.getPath());
            if (host !== TARGET_HOST || path !== TARGET_PATH) {
                return;
            }
            activate("passport_request_uri", activeRpcId);
            trackedBasic[objectId(tools)] = true;
            capturedHost = host;
            capturedPath = path;
            hookCalled("BasicParamsTools.buildUri", overload);
            if (!uriReported) {
                uriReported = emit("request_uri", {
                    overload: overload,
                    host: host,
                    path: path,
                });
                maybeComplete();
            }
        }

        const buildUri = Tools.buildUri.overload();
        buildUri.implementation = function () {
            const uri = buildUri.call(this);
            observeUri(this, uri, "");
            return uri;
        };

        const buildUriWithMap = Tools.buildUri.overload("java.util.Map");
        buildUriWithMap.implementation = function (params) {
            const uri = buildUriWithMap.call(this, params);
            observeUri(this, uri, "java.util.Map");
            return uri;
        };

        const getCrypted = Tools.getCryptedParams.overload("java.util.Map");
        getCrypted.implementation = function (params) {
            const relevant = captureStarted &&
                (trackedBasic[objectId(this)] ||
                 (capturedHost === TARGET_HOST && capturedPath === TARGET_PATH));
            if (relevant) {
                hookCalled("BasicParamsTools.getCryptedParams", "java.util.Map");
                reportInner();
            }
            const result = getCrypted.call(this, params);
            if (relevant) {
                reportCommon(
                    params,
                    commonBefore,
                    "BasicParamsTools.getCryptedParams input fallback"
                );
                try {
                    reportRsa(this.mRsaManager.value);
                } catch (error) {
                    debug("rsa_active", "inspection_failed");
                }
                reportOuter(result, "BasicParamsTools.getCryptedParams(java.util.Map)");
            }
            return result;
        };
    });

    install("UserCenterRsaManager.initPubKey", function () {
        const Manager = Java.use(
            "com.qihoo360.accounts.api.auth.p.UserCenterRsaManager"
        );
        const init = Manager.initPubKey.overload("android.content.Context");
        init.implementation = function (context) {
            const result = init.call(this, context);
            if (captureStarted && rsaDefaults[objectId(this)] !== undefined) {
                reportRsa(this);
            }
            return result;
        };
    });

    install("HttpGetRequest.setUri", function () {
        const Request = Java.use(
            "com.qihoo360.accounts.api.http.HttpGetRequest"
        );
        const setUri = Request.setUri.overload("java.net.URI");
        setUri.implementation = function (uri) {
            if (uri !== null && String(uri.getHost()) === TARGET_HOST &&
                String(uri.getPath()) === TARGET_PATH) {
                activate("passport_http_request", activeRpcId);
                hookCalled("HttpGetRequest.setUri", "java.net.URI");
                trackedRequests[objectId(this)] = true;
                capturedHost = TARGET_HOST;
                capturedPath = TARGET_PATH;
                if (!uriReported) {
                    uriReported = emit("request_uri", {
                        overload: "HttpGetRequest.setUri(java.net.URI)",
                        host: TARGET_HOST,
                        path: TARGET_PATH,
                    });
                }
            }
            return setUri.call(this, uri);
        };
    });

    install("HttpPostRequest", function () {
        const Request = Java.use(
            "com.qihoo360.accounts.api.http.HttpPostRequest"
        );
        const setPostParameters = Request.setPostParameters.overload("java.util.Map");
        setPostParameters.implementation = function (params) {
            const identityMatches = trackedRequests[objectId(this)] === true;
            const targetKnown = captureStarted && capturedHost === TARGET_HOST &&
                capturedPath === TARGET_PATH;
            if (targetKnown) {
                hookCalled("HttpPostRequest.setPostParameters", "java.util.Map");
                if (!identityMatches) {
                    debug("outer_params", "request_identity_mismatch_fallback_used");
                }
                reportOuter(params, "HttpPostRequest.setPostParameters(java.util.Map)");
            } else if (captureStarted) {
                debug("outer_params", "target_uri_not_seen");
            }
            return setPostParameters.call(this, params);
        };

        const send = Request.a.overload("java.net.HttpURLConnection");
        send.implementation = function (connection) {
            if (!networkReported) {
                try {
                    const url = connection.getURL();
                    const host = String(url.getHost());
                    const path = String(url.getPath());
                    if (host === TARGET_HOST && path === TARGET_PATH) {
                        activate("passport_http_connection", activeRpcId);
                        hookCalled(
                            "HttpPostRequest.a",
                            "java.net.HttpURLConnection"
                        );
                        let userAgent = connection.getRequestProperty("User-Agent");
                        userAgent = userAgent === null ? null : String(userAgent);
                        networkReported = emit("http_request", {
                            method: "POST",
                            host: host,
                            path: path,
                            user_agent: userAgent,
                        });
                        maybeComplete();
                    }
                } catch (error) {
                    debug("http_request", "inspection_failed");
                }
            }
            return send.call(this, connection);
        };
    });

    emit("ready", {
        package: "com.qihoo.smarthome",
        scope: "first password RPC or passport.360.cn/request.php request only",
    });
});
