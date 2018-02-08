//
//  ViewController.swift
//  XTool-Mac
//
//  Created by tpeng on 2018/2/7.
//  Copyright © 2018年 tpeng. All rights reserved.
//

import Cocoa



class ViewController: NSViewController {
    let ptManager = PTManager.instance
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        ptManager.delegate = self;
        ptManager.connect(portNumber: PORT_NUMBER)
        for ip in getIFAddresses() {
            print(ip)
        }
//        list()
//        list_app()
//        launch_app()
        
//        install_app()

        
    }
    
    func listApp() {
    }
    

    
    func list() {
        var i: CInt = 0
        var device_list: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>? = nil
        
        
        idevice_get_device_list(&device_list, &i)
        
        print("number of devices: \(i)")
        
        let array = Array(UnsafeBufferPointer(start: device_list, count: Int(i)))
        
        for var device in array {
            
            let deviceName = String(cString:device!)
            print("\tdevice: \(deviceName)")
            
        }
        
        idevice_device_list_free(device_list)
    }
    
    func test_func() {
        print("ok!!")
    }
    
    
    func sendIP () {
        self.ptManager.sendObject(object: self.getIFAddresses().first, type: PTType.string.rawValue)
    }
    
    @IBAction func sendIPButtonClick(_ sender: NSButton) {
//        launch_app()

        install_app {
            print("ok!!!")
                    DispatchQueue.global().async {
                        let deadlineTime = DispatchTime.now() + 0.5
                        DispatchQueue.main.asyncAfter(deadline: deadlineTime) {
                            launch_app()
                            self.sendIP()
                        }
                    }

        }
        
//        DispatchQueue(label: "ccc").async {
////            install_app()
//
//        }

        
    }
    override var representedObject: Any? {
        didSet {
            // Update the view, if already loaded.
        }
    }
    
    
    func getIFAddresses() -> [String] {
        var addresses = [String]()
        
        // Get list of all interfaces on the local machine:
        var ifaddr : UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return [] }
        guard let firstAddr = ifaddr else { return [] }
        
        // For each interface ...
        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let flags = Int32(ptr.pointee.ifa_flags)
            let addr = ptr.pointee.ifa_addr.pointee
            
            // Check for running IPv4, IPv6 interfaces. Skip the loopback interface.
            if (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) {
                if addr.sa_family == UInt8(AF_INET)  {
                    
                    // Convert interface address to a human readable string:
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if (getnameinfo(ptr.pointee.ifa_addr, socklen_t(addr.sa_len), &hostname, socklen_t(hostname.count),
                                    nil, socklen_t(0), NI_NUMERICHOST) == 0) {
                        let address = String(cString: hostname)
                        addresses.append(address)
                    }
                }
            }
        }
        freeifaddrs(ifaddr)
        return addresses
    }
    
}


extension ViewController: PTManagerDelegate {
    
    func peertalk(shouldAcceptDataOfType type: UInt32) -> Bool {
        return true
    }
    
    func peertalk(didReceiveData data: Data, ofType type: UInt32) {
        if type == PTType.number.rawValue {
            let count = data.convert() as! Int
            print(count)
        } else if type == PTType.image.rawValue {
            let image = NSImage(data: data)
        }
    }
    
    func peertalk(didChangeConnection connected: Bool) {
        print("Connection: \(connected)")
    }
    
}
