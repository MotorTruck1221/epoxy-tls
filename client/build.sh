#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

mkdir out/ || true
rm -r pkg/ || true
mkdir pkg/

RUSTFLAGS='-C target-feature=+atomics,+bulk-memory' cargo build --target wasm32-unknown-unknown -Z build-std=panic_abort,std --release "$@"
echo "[epx] cargo finished"
wasm-bindgen --weak-refs --target no-modules --no-modules-global epoxy --out-dir out/ ../target/wasm32-unknown-unknown/release/epoxy_client.wasm
echo "[epx] wasm-bindgen finished"

if ! [ "${RELEASE:-0}" = "1" ]; then
	WASMOPTFLAGS="-g"
else
	WASMOPTFLAGS=""
fi

mv out/epoxy_client_bg.wasm out/epoxy_client_unoptimized.wasm
time wasm-opt $WASMOPTFLAGS -Oz --vacuum --dce --enable-threads --enable-bulk-memory out/epoxy_client_unoptimized.wasm -o out/epoxy_client_bg.wasm
echo "[epx] wasm-opt finished"

AUTOGENERATED_SOURCE=$(<"out/epoxy_client.js")
# patch for websocket sharedarraybuffer error
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//getObject(arg0).send(getArrayU8FromWasm0(arg1, arg2)/getObject(arg0).send(new Uint8Array(getArrayU8FromWasm0(arg1, arg2)).buffer}
# patch for safari OOM errors on safari iOS 16/older devices
# also lowers maximum memory from default of 1GB to 512M on non-iOS and to 256M on iOS
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//maximum:16384,shared:true/maximum:/iPad|iPhone|iPod/.test(navigator.userAgent)?4096:8192,shared:true}
# patch to set proper wasm path
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//'_bg.wasm'/'.wasm'}
echo "$AUTOGENERATED_SOURCE" > pkg/epoxy.js

cp pkg/epoxy.js pkg/epoxy-module.js
echo "export default epoxy;" >> pkg/epoxy-module.js

WASM_BASE64=$(base64 -w0 out/epoxy_client_bg.wasm)
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//__wbg_init(input, maybe_memory) \{/__wbg_init(maybe_memory) \{$'\n'let input=\'data:application/wasm;base64,$WASM_BASE64\'}
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//return __wbg_finalize_init(instance, module);/__wbg_finalize_init(instance, module);$'\n'return epoxy;}
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//if (wasm !== undefined) return wasm;/if (wasm !== undefined) return epoxy;}

echo "$AUTOGENERATED_SOURCE" > pkg/epoxy-bundled.js

cp pkg/epoxy-bundled.js pkg/epoxy-module-bundled.js
echo "export default epoxy;" >> pkg/epoxy-module-bundled.js

AUTOGENERATED_TYPEDEFS=$(<"out/epoxy_client.d.ts")
AUTOGENERATED_TYPEDEFS=${AUTOGENERATED_TYPEDEFS%%export class IntoUnderlyingByteSource*}
echo "$AUTOGENERATED_TYPEDEFS" > pkg/epoxy-module.d.ts
echo -e "}\ndeclare type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;" >> pkg/epoxy-module.d.ts
echo -e "export default function epoxy(module_or_path?: InitInput | Promise<InitInput>, maybe_memory?: WebAssembly.Memory): Promise<typeof wasm_bindgen>;" >> pkg/epoxy-module.d.ts
echo "$AUTOGENERATED_TYPEDEFS" > pkg/epoxy-module-bundled.d.ts
echo -e "}\nexport default function epoxy(maybe_memory?: WebAssembly.Memory): Promise<typeof wasm_bindgen>;" >> pkg/epoxy-module-bundled.d.ts
echo "$AUTOGENERATED_TYPEDEFS" > pkg/epoxy-bundled.d.ts
echo -e "}\ndeclare function epoxy(maybe_memory?: WebAssembly.Memory): Promise<typeof wasm_bindgen>;" >> pkg/epoxy-bundled.d.ts

cp out/epoxy_client.d.ts pkg/epoxy.d.ts
cp out/epoxy_client_bg.wasm pkg/epoxy.wasm

rm -r out/
echo "[epx] done!"
