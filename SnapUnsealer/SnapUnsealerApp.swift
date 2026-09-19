//
//  SnapUnsealerApp.swift
//  SnapUnsealer
//
//  Created by Nam Nguyen on 19/9/26.
//

import SwiftUI

@main
struct SnapUnsealerApp: App {
    init() {
        ProcessHardening.disableCoreDumps()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}
