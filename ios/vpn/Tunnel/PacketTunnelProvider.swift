//
//  PacketTunnelProvider.swift
//  Tunnel
//
//  Created by Gregory Hazel on 7/9/19.
//  Copyright © 2019 Clostra. All rights reserved.
//

import NetworkExtension
import os.log

private enum NewNodeError: Error {
    case initializationError
}

private extension String {
    static let applicationGroupIdentifier = "group.com.newnode.vpn"
    static let wormholeStatisticMessageIdentifier = "DisplayStats"
}

private extension Notification.Name {
    static let displayStatistic = Notification.Name("DisplayStats")
}

final class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        super.startTunnel(options: options, completionHandler: completionHandler)

        NotificationCenter.default.addObserver(self, selector:#selector(displayStats), name: .displayStatistic, object: nil)

        let cachesPath = NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).last!
        chdir(cachesPath)

        NewNode.logLevel = 1
        let d = NewNode.connectionProxyDictionary
        let port = (d?["HTTPPort"] ?? 0) as! Int

        if (port == 0) {
            os_log("Error: NewNode could not be initialized")
            completionHandler(NewNodeError.initializationError)
            return
        }
        os_log("NewNode initialized on %d", port)
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let proxySettings = NEProxySettings()
        proxySettings.autoProxyConfigurationEnabled = true
        proxySettings.excludeSimpleHostnames = true
        proxySettings.matchDomains = [""]

        // in order of precedence:
        // 1
        //proxySettings.proxyAutoConfigurationJavaScript = "function FindProxyForURL(url, host) {return \"PROXY 127.0.0.1:\(port); SOCKS 127.0.0.1:\(port); DIRECT\";}";

        // 2
        proxySettings.proxyAutoConfigurationURL = URL(string: "http://127.0.0.1:\(port)/proxy.pac")

        // 3
        proxySettings.httpEnabled = true
        proxySettings.httpServer = NEProxyServer(address: "127.0.0.1", port: Int(port))
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = NEProxyServer(address: "127.0.0.1", port: Int(port))

        settings.proxySettings = proxySettings
        
        self.setTunnelNetworkSettings(settings) { (error: Error?) in
            os_log("setTunnelNetworkSettings %{public}@", error.debugDescription)
            completionHandler(error)
        }
    }

    @objc func displayStats(notification: NSNotification) {
        let o = notification.userInfo
        let wormhole = MMWormhole(applicationGroupIdentifier: .applicationGroupIdentifier, optionalDirectory: nil)
        wormhole.passMessageObject(o as NSDictionary?, identifier: .wormholeStatisticMessageIdentifier)
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
