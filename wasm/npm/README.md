# Sahyadri WASM SDK

An integration wrapper around [`sahyadri-wasm`](https://www.npmjs.com/package/sahyadri-wasm) module that uses [`websocket`](https://www.npmjs.com/package/websocket) W3C adaptor for WebSocket communication.

This is a Node.js module that provides bindings to the Sahyadri WASM SDK strictly for use in the Node.js environment. The web browser version of the SDK is available as part of official SDK releases at [https://github.com/sahyadrinet/rusty-sahyadri/releases](https://github.com/sahyadrinet/rusty-sahyadri/releases)

## Usage

Sahyadri NPM module exports include all WASM32 bindings.
```javascript
const sahyadri = require('sahyadri');
console.log(sahyadri.version());
```

## Documentation

Documentation is available at [https://sahyadri.aspectron.org/docs/](https://sahyadri.aspectron.org/docs/)


## Building from source & Examples

SDK examples as well as information on building the project from source can be found at [https://github.com/sahyadrinet/rusty-sahyadri/tree/master/wasm](https://github.com/sahyadrinet/rusty-sahyadri/tree/master/wasm)

## Releases

Official releases as well as releases for Web Browsers are available at [https://github.com/sahyadrinet/rusty-sahyadri/releases](https://github.com/sahyadrinet/rusty-sahyadri/releases).

Nightly / developer builds are available at: [https://aspectron.org/en/projects/sahyadri-wasm.html](https://aspectron.org/en/projects/sahyadri-wasm.html)

