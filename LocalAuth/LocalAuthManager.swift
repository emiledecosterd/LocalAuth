//
//  LocalAuthManager.swift
//  LocalAuth
//
//  Created by Emile Décosterd on 05.08.16.
//  Copyright © 2016 Emile Décosterd. All rights reserved.
//

import Foundation
import LocalAuthentication


// MARK: LocalAuthError enum

public enum LocalAuthError: ErrorType {
  case System(message:String?)
  case Unavailable
  case Unknown
}


// MARK: - LocalAuthManager class
// MARK: -
public class LocalAuthManager {
  
  
  // MARK: Properties
  
  private var context: LAContext
  private var localizedReason: String?
  
  public static var sharedManager = LocalAuthManager()
  
  
  // MARK: Initialisation
  
  public init(){
    self.context = LAContext()
  }
  
  public convenience init(localizedReason: String) {
    self.init()
    self.localizedReason = localizedReason
  }
  
  
  // MARK: Public methods and computed properties
  
  public var touchIDAvailable: Bool {
    if let policy = LAPolicy(rawValue: Int(kLAPolicyDeviceOwnerAuthenticationWithBiometrics))  {
      if let _ = try? canEvaluatePolicy(policy){return true}
    }
    return false
  }
  
  public var secretAvailable: Bool {
    if let policy = LAPolicy(rawValue: Int(kLAPolicyDeviceOwnerAuthentication))  {
      if let _ = try? canEvaluatePolicy(policy){return true}
    }
    return false
  }
  
  // Attention! The completion block will be executed on the main thread.
  public func loginUsingTouchID(completion:(Bool)->()) throws {
    do{
      try evaluatePolicy(kLAPolicyDeviceOwnerAuthenticationWithBiometrics, completion: completion)
    }catch let error as LocalAuthError {
      throw error
    }
  }
  
  // Attention! The completion block will be executed on the main thread.
  public func loginUsingSecret(completion: (Bool)->()) throws {
    do{
      try evaluatePolicy(kLAPolicyDeviceOwnerAuthentication, completion: completion)
    }catch let error as LocalAuthError {
      throw error
    }
  }
  
  
  // MARK: Private methods
  
  private func canEvaluatePolicy(policy: LAPolicy) throws{
    var error: NSError? = nil
    guard context.canEvaluatePolicy(policy, error: &error) else {
      throw LocalAuthError.System(message: error?.localizedDescription)
    }
  }
  
  // The completion block will be executed on the main thread.
  private func evaluatePolicy(policy: Int32, completion: (Bool)->()) throws {
    do{
      guard let policy = LAPolicy(rawValue: Int(policy)) else {
        throw LocalAuthError.Unknown
      }
      
      try canEvaluatePolicy(policy)
      
      var authError: LocalAuthError? = nil
      if localizedReason == nil {
        localizedReason = "You need to authenticate in order to access the app's content.".localized
      }
      context.evaluatePolicy(policy, localizedReason: localizedReason!, reply: {(success, evaluateError) -> Void in
        if let error = evaluateError {
          authError =  LocalAuthError.System(message: error.localizedDescription)
        }
        dispatch_async(dispatch_get_main_queue()) {
          completion(success)
        }
      })
      
      if let error = authError {
        throw error
      }
      
    }catch let error as LocalAuthError {
      throw error
    }
  }
  
}
