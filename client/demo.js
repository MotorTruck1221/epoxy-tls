importScripts("epoxy-bundled.js");
onmessage = async (msg) => {
    console.debug("recieved:", msg);
    let [feature_test, multiparallel_test, parallel_test, multiperf_test, perf_test, ws_test, tls_test, dns_test] = msg.data;
    console.log(
        "%cWASM is significantly slower with DevTools open!",
        "color:red;font-size:3rem;font-weight:bold"
    );

    const log = (str) => {
        console.warn(str);
        postMessage(str);
    }

    const { EpoxyClient } = await epoxy();

    const tconn0 = performance.now();
    // args: websocket url, user agent, redirect limit 
    let epoxy_client = await new EpoxyClient("wss://localhost:4000", navigator.userAgent, 10);
    const tconn1 = performance.now();
    log(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);

    const test_mux = async (url) => {
        const t0 = performance.now();
        await epoxy_client.fetch(url);
        const t1 = performance.now();
        return t1 - t0;
    };

    const test_native = async (url) => {
        const t0 = performance.now();
        await fetch(url, { cache: "no-store" });
        const t1 = performance.now();
        return t1 - t0;
    };

    if (feature_test) {
        for (const url of [
            ["https://httpbin.org/get", {}],
            ["https://httpbin.org/gzip", {}],
            ["https://httpbin.org/brotli", {}],
            ["https://httpbin.org/redirect/11", {}],
            ["https://httpbin.org/redirect/1", { redirect: "manual" }],
        ]) {
            let resp = await epoxy_client.fetch(url[0], url[1]);
            console.warn(url, resp, Object.fromEntries(resp.headers));
            console.warn(await resp.text());
        }
    } else if (multiparallel_test) {
        const num_tests = 10;
        let total_mux_minus_native = 0;
        for (const _ of Array(num_tests).keys()) {
            let total_mux = 0;
            await Promise.all([...Array(num_tests).keys()].map(async i => {
                log(`running mux test ${i}`);
                return await test_mux("https://httpbin.org/get");
            })).then((vals) => { total_mux = vals.reduce((acc, x) => acc + x, 0) });
            total_mux = total_mux / num_tests;

            let total_native = 0;
            await Promise.all([...Array(num_tests).keys()].map(async i => {
                log(`running native test ${i}`);
                return await test_native("https://httpbin.org/get");
            })).then((vals) => { total_native = vals.reduce((acc, x) => acc + x, 0) });
            total_native = total_native / num_tests;

            log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
            log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
            log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
            total_mux_minus_native += total_mux - total_native;
        }
        total_mux_minus_native = total_mux_minus_native / num_tests;
        log(`total mux - native (${num_tests} tests of ${num_tests} reqs): ${total_mux_minus_native} ms or ${total_mux_minus_native / 1000} s`);
    } else if (parallel_test) {
        const num_tests = 10;

        let total_mux = 0;
        await Promise.all([...Array(num_tests).keys()].map(async i => {
            log(`running mux test ${i}`);
            return await test_mux("https://httpbin.org/get");
        })).then((vals) => { total_mux = vals.reduce((acc, x) => acc + x, 0) });
        total_mux = total_mux / num_tests;

        let total_native = 0;
        await Promise.all([...Array(num_tests).keys()].map(async i => {
            log(`running native test ${i}`);
            return await test_native("https://httpbin.org/get");
        })).then((vals) => { total_native = vals.reduce((acc, x) => acc + x, 0) });
        total_native = total_native / num_tests;

        log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
        log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
        log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
    } else if (multiperf_test) {
        const num_tests = 10;
        let total_mux_minus_native = 0;
        for (const _ of Array(num_tests).keys()) {
            let total_mux = 0;
            for (const i of Array(num_tests).keys()) {
                log(`running mux test ${i}`);
                total_mux += await test_mux("https://httpbin.org/get");
            }
            total_mux = total_mux / num_tests;

            let total_native = 0;
            for (const i of Array(num_tests).keys()) {
                log(`running native test ${i}`);
                total_native += await test_native("https://httpbin.org/get");
            }
            total_native = total_native / num_tests;

            log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
            log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
            log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
            total_mux_minus_native += total_mux - total_native;
        }
        total_mux_minus_native = total_mux_minus_native / num_tests;
        log(`total mux - native (${num_tests} tests of ${num_tests} reqs): ${total_mux_minus_native} ms or ${total_mux_minus_native / 1000} s`);
    } else if (perf_test) {
        const num_tests = 10;

        let total_mux = 0;
        for (const i of Array(num_tests).keys()) {
            log(`running mux test ${i}`);
            total_mux += await test_mux("https://httpbin.org/get");
        }
        total_mux = total_mux / num_tests;

        let total_native = 0;
        for (const i of Array(num_tests).keys()) {
            log(`running native test ${i}`);
            total_native += await test_native("https://httpbin.org/get");
        }
        total_native = total_native / num_tests;

        log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
        log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
        log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
    } else if (ws_test) {
        let ws = await epoxy_client.connect_ws(
            () => console.log("opened"),
            () => console.log("closed"),
            err => console.error(err),
            msg => console.log(msg),
            "wss://echo.websocket.events",
            [],
            "localhost"
        );
        while (true) {
            await ws.send("data");
            await (new Promise((res, _) => setTimeout(res, 100)));
        }
    } else if (tls_test) {
        let decoder = new TextDecoder();
        let ws = await epoxy_client.connect_tls(
            () => console.log("opened"),
            () => console.log("closed"),
            err => console.error(err),
            msg => { console.log(msg); console.log(decoder.decode(msg)) },
            "alicesworld.tech:443",
        );
        await ws.send("GET / HTTP 1.1\r\nHost: alicesworld.tech\r\nConnection: close\r\n\r\n");
        await ws.close();
    } else if (dns_test) {
        let total = 0;
        for (const i of Array(100).keys()) {
            const t0 = performance.now();
            const res = await epoxy_client.resolve("coolelectronics.me");
            const t1 = performance.now();
            log(`resolving coolelectronics.me #${i} took ${t1 - t0}ms or ${(t1 - t0) / 1000}s, resolved to ${res}`);
            total += t1 - t0;
        }
        total = total / 100;
        log(`avg resolving coolelectronics.me took ${total}ms or ${total / 1000}s`);
    } else {
        let resp = await epoxy_client.fetch("https://httpbin.org/get");
        console.warn(resp, Object.fromEntries(resp.headers));
        console.warn(await resp.text());
    }
    log("done");
};
