//EXAMPLE 3
console.log("=== AES ===");
var plaintext = "hallo welt test furchtbar hello world";
/*
var key = CryptoJS.enc.Hex.parse("2aab3106c7f6a6edeef9275cc58bc69a57cd55b679207233ab6300b6a71fc77a");
var iv = CryptoJS.enc.Hex.parse("727f745b3fb85a912269b56bf83ae190");
*/
var key = CryptoJS.enc.Base64.parse("KqsxBsf2pu3u+SdcxYvGmlfNVbZ5IHIzq2MAtqcfx3o=");
var iv = CryptoJS.enc.Base64.parse("cn90Wz+4WpEiabVr+DrhkA==");
var ciphertext = CryptoJS.AES.encrypt(plaintext, key, {iv: iv, mode: CryptoJS.mode.CFB});
console.log("Plaintext: " + plaintext);
console.log("Key:       " + CryptoJS.enc.Base64.stringify(key));
console.log("IV:        " + CryptoJS.enc.Base64.stringify(iv));
//console.log("Encrypted: " + CryptoJS.enc.Base64.stringify(ciphertext.toString(CryptoJS.enc.Hex)));
console.log("Encrypted: " + ciphertext);
console.log("Decrypted: " + CryptoJS.AES.decrypt(ciphertext.toString(), key, {iv: iv, mode: CryptoJS.mode.CFB}).toString(CryptoJS.enc.Utf8));

// EXAMPLE 4
console.log("=== RSA ===");
function _arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}

function _base64ToArrayBuffer(base64) {
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
/*
window.crypto.subtle.generateKey(
    {
        name: "RSA-OAEP",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
)
.then(function(key){
    //returns a keypair object
    console.log(key);
    console.log(key.publicKey);
    console.log(key.privateKey);
    window.crypto.subtle.exportKey("pkcs8", key.privateKey).then(function(result){
        console.log(result);
        //console.log(_arrayBufferToBase64(result));
    })
})
.catch(function(err){
    console.error(err);
});*/

window.crypto.subtle.importKey(
    /*
    "pkcs8",
    _base64ToArrayBuffer('MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI1VCixSed+4ICAgPoMBQGCCqGSIb3DQMHBAgyc8sqqakBgQSCBMiJhg1BfdhIuagNLs9KZGI5e9w40fuG2e6lpMhppf6BtWf9Ut6P6Myt8SGU/SbbN2PEc7YSseFEOC2OTKI/7r4Gi0roj3jyVwSa1dHK+rGFhoXKT5/wpCQnLaXCt3VnAwikDRQ//2nTPIG/5dX+jJANGupYlq/QW6FUnJaAkYcadOptfJBZfXIzRT21WzJWO+Fvm3ljnBZgEITjCtxRKO9BXtlKY70IXLOPdEZ8Y+hsD7VDnQH7OOgLH1gNTw31mQUHaHvEmJKLlPfvtqN8PfCr4tc5wezaCJ+Dul/QmbrppVEX1y72o+As8WE2KeFqzKof9vQ9oztRePVxrgpLfHWDgaHzNVHBHD3qOshkNNvZX+SjOe5jIqPjRoujRSNcZQrlWxOGOKWlr9DJ7yb7ovl18mQE2eI/WqswG1kXMcvJTMnayPllc12hlpjrpyqKxV1PiTFB3JohuOWR7+OFxB7IrpYlQOnWyzrN0OXqu/IeGMybt2QcwITSuhF2TDJM4tT2h7+kK9b2ELUfmWF8Cu3VCKaN8SRq/bIFHUnkBCvyAL9o+DMrkXn98J8hvEA28WeiEQaldq+d91uZ26b3Q5Q+T2fcXQggmfiJGHNTfmns4wx/N23CBEjReQj4z2VTxLvh9h+Rtcu4DOyq0Izz44rCw3OaBc6Bb6LII1X/aqi6QbCISV0A92yfx95y2nw9vxG3N1r8f7L96Ym6/DTznF1pgWRXw1HiCuxajIugOqLh1BFrFL3QgsTmkIOs8lXXXI13dfatGw84y0rqglwWpIJZiZrOqHGCm0oN/gyOGy6aq79ZGFvr/ffo2dAYN17UFUgfCJzfzELf8i+UbUomp0qXe/hYlcNf43d6Sm1BTnY5rxsiuTPBfbUFd+MXPPQOc3T+hiB9vVQYNafafAkkMTTQGjejPcoCOX1GTkdp/3lMzNJjQRZpQ1fU7N7QdRg7tB9F2iC61t5CW92JDDyxmIlKP/vN2TNvyGtdcUvY2g2BcAfyXrRwzdba90XCtiX5I69WfUOxv121c9ZIEBi7aEcQ6KYvZEwbAAjCyWomlLNTtRlefencEzMMQxWhPH8gGdjLSxttVBnUyk0g/bVw1W8sdmqjzzE7XlFWbSW3vAIbrlQoHGpprn2mEQCzXnIj+ciDNc9P4mwPXkHays4zry4UI0qkFiM4DCfUfkVM72dYA+wE6CMXBXcyrretp3d8fZRzn2kg+bZHTThKnf9XGvh3CFSWai73StOY9MAeGSz0vEw3BWbmPhwF4aYD6KlrE/xsSQikNWSI3LhM2ULzUFlq6c7p+fA9/4fcWduzQKx94/PXyTui/dZiSHkU52TUjySGVyPdjrA/vNXAs0bkSrUQa+3VADFCaJQRtmOfs/FjDOxCvBrkidt/s3S2blBl2SPsfISgCSvjNpKsxTdA15fykHjc8S/fm0oF45xqjE5QJkNDbXPlRIB+ggHz3nkp/n8+vQDjKicmU9VEpMWfR70CdgvI/f3W/TXJi64u5qCPlRZw/POHunjBC6LgnZ6iQKjJAoLoLdhcYEbYMwqeulmWObO1dIBJRyIED5QkRgA2NI1JezOotLWBWAYSk1oWtMNw3cPxbuVcGImeuYv1Am9zzCtwruSPYhI='),
    */
    "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
    {
  kty: "RSA",
  d: "UKhHcXv56T3pnJFoPWY9jwdJY38BgUxOg1L8t9OZfZv3K8G9yvqm-j7KbprKOgVlb-uVoucP8C4NQRkbLA0crMDlYYz5_yJLue1AOL4qV1DNJRXY9a9Rbg4thvXIa9pSaxRKJVCJjd9I-PFFWKSMm9uhTZh556_ST2wyk3PymuV2Xo6lmVEVKWQxnibFd5pS4N-w0CcGuhvkOLKkkFePx-uxckAeXDU5dccd7z2KdFB5qr0iQ43LMdjuJGP5tAH4xNd-YssXUuwK1p1TPYdcu1n-WmIbvfwPXa5E9idUZD5Zzuhz1nz5wAdBCeyYRjhtVHZlSOzXRcy5fJewvzlHgQ",
  e: "AQAB",
  use: "enc",
  alg: "RSA-OAEP-256",
  n: "rOvtWzw7kdLaE2_3JYNt003T48O2RgJcKqfO-4W1unQgl1n_OAVPHxNozUCdv7KMUT29z-LQRHP7Z1X__jGIaTr3STAOtN_1P78ZUOjFFMDReo1lN_gWSaRc3a8Ulv-XiBD-ZawPsn4ggv70opTkbRrd4lo4_4mANzEzPZlLr_r09hXi1w_T59LuSTHpuE383K9q7xvy3BIx0TN8nAHzh_Em9aWAPy_citFkEcsoW29hT2uA4_CZWmaIxH_yE4FwiiT5Cn9mLWiGYbAhTg4nn4pq44TDrTNY3qWha35w7bzqRpl4mVN2cXr0DeWCJUvqyKUIzwJK3iGhAAmq4N4AtQ",
  ext: true
},
    /*
    {   //this is an example jwk key, other key types are Uint8Array objects
        kty: "RSA",
        e: "AQAB",
        n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
        alg: "RSA-OAEP-256",
        ext: true,
    },
    */
    {
        name: "RSA-OAEP",
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true,
    ["encrypt"]
).then(function(key){
    console.log(key);
    console.log(key.publicKey);
    console.log(key.privateKey);
}).catch(function(err){
    console.log(err);
});