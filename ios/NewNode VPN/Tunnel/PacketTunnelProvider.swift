//
//  PacketTunnelProvider.swift
//  Tunnel
//
//  Created by Gregory Hazel on 7/9/19.
//  Copyright © 2019 Clostra. All rights reserved.
//

import NetworkExtension
import os.log

enum NewNodeError: Error {
    case initializationError
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        super.startTunnel(options: options, completionHandler: completionHandler)

        let cachesPath = NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).last!
        chdir(cachesPath)

        o_debug = 1
        let app_name = Bundle.main.infoDictionary?["CFBundleDisplayName"] as! String
        let app_id = Bundle.main.infoDictionary?["CFBundleIdentifier"] as! String
        var http_port: UInt16 = 8006
        var socks_port: UInt16 = 8007
        newnode_init(app_name, app_id, &http_port, &socks_port, Optional<(Optional<UnsafePointer<Int8>>, Optional<(Bool) -> ()>) -> ()> {
            url, cb in
            let url = String(cString: url!)
            os_log("https: %{public}s", url)
            URLSession.shared.downloadTask(with: URL(string: url)!) {
                urlOrNil, responseOrNil, errorOrNil in
                if let error = errorOrNil {
                    os_log("https error: %@", error.localizedDescription)
                }
                cb!(errorOrNil != nil)
            }.resume()
        })
        if (http_port == 0 || socks_port == 0) {
            os_log("Error: NewNode could not be initialized")
            completionHandler(NewNodeError.initializationError)
            return
        }
        os_log("NewNode initialized on %d,%d", http_port, socks_port)
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let proxySettings = NEProxySettings()
        proxySettings.autoProxyConfigurationEnabled = true
        proxySettings.excludeSimpleHostnames = true
        proxySettings.matchDomains = [""]

        // in order of precedence:
        // 1
        //proxySettings.proxyAutoConfigurationJavaScript = "function FindProxyForURL(url, host) {return \"PROXY 127.0.0.1:\(http_port); SOCKS 127.0.0.1:\(socks_port); DIRECT\";}";

        // 2
        proxySettings.proxyAutoConfigurationURL = URL(string: "http://127.0.0.1:\(http_port)/proxy.pac")

        // 3
        proxySettings.httpEnabled = true
        proxySettings.httpServer = NEProxyServer(address: "127.0.0.1", port: Int(http_port))
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = NEProxyServer(address: "127.0.0.1", port: Int(http_port))

        settings.proxySettings = proxySettings
        
        self.setTunnelNetworkSettings(settings) { (error: Error?) in
            os_log("setTunnelNetworkSettings %{public}@", error.debugDescription)
            completionHandler(error)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Add code here to start the process of stopping the tunnel.
        os_log("stopTunnel reason:%d", reason.rawValue)
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Add code here to handle the message.
        if let handler = completionHandler {
            handler(messageData)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        // Add code here to get ready to sleep.
        completionHandler()
    }
    
    override func wake() {
        // Add code here to wake up.
    }
}
