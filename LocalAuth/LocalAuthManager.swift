/*
 * Copyright (c) 2016 Emile Décosterd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


import Foundation
import LocalAuthentication


// MARK: LocalAuthError enum

/**
 *  Possible errors
 *  - System: Error issued by the system.
 *  - Unavailable: Chosen policy not available
 *  - Unknown: Unknown error
 */
public enum LocalAuthError: Error {
  case system(message:String?)
  case unavailable
  case unknown
}


// MARK: - LocalAuthManager class
// MARK: -

/**
 * Class that manages the authentication using TouchID and/or device's passcode.
 * Can be used as a singleton, accessing the property `sharedManager`.
 */
public final class LocalAuthManager {
  
  
  // MARK: Properties
  
  fileprivate var context: LAContext
  fileprivate var localizedReason: String?

  ///Allows to use this class as a singleton.
  public static var sharedManager = LocalAuthManager()

  
  // MARK: Initialisation
  
  /// Standard initialisation
  public init(){
    self.context = LAContext()
  }
  
  /**
   * Advanced initialisation
   * - Parameter localizedReason: The reason why we ask the user to authenticate.
   */
  public convenience init(localizedReason: String) {
    self.init()
    self.localizedReason = localizedReason
  }
  
  
  // MARK: Public methods and computed properties
  
  /// Computed property to know if touchID is available on the current device, and/or if it is set.
  public var touchIDAvailable: Bool {
    if let policy = LAPolicy(rawValue: Int(kLAPolicyDeviceOwnerAuthenticationWithBiometrics))  {
      if let _ = try? canEvaluatePolicy(policy){return true}
    }
    return false
  }
  
  /// Computed property to know if passcode is set.
  public var secretAvailable: Bool {
    if let policy = LAPolicy(rawValue: Int(kLAPolicyDeviceOwnerAuthentication))  {
      if let _ = try? canEvaluatePolicy(policy){return true}
    }
    return false
  }
  
  /**
   * Displays the TouchID login alert. Throws an error if not available or if the authentication fails.
   
   * - Parameter completion:  A completion block to be executed once the login is complete. First parameter of this completion block is wether or not the authentication has been successful.
   
   * - Throws: An error that appeared while checking availability or authenticating.
   
   * - Warning: The completion block is executed on the main thread.
   */
  public func loginUsingTouchID(_ completion:@escaping (Bool)->()) throws {
    do{
      try evaluatePolicy(kLAPolicyDeviceOwnerAuthenticationWithBiometrics, completion: completion)
    }catch let error as LocalAuthError {
      throw error
    }
  }
  
  /**
   * Displays the passcode authentication view. If TouchID is available, displays the TouchID login alert. Throws an error if no passcode is set or if the authentication fails.
   
   * - Parameter completion: A completion block to be executed once the login is complete. First parameter of this completion block is wether or not the authentication has been successful.
   
   * - Throws: An error that appeared while checking availability or authenticating.
   
   * - Warning: The completion block is executed on the main thread.
   */
  public func loginUsingSecret(_ completion: @escaping (Bool)->()) throws {
    do{
      try evaluatePolicy(kLAPolicyDeviceOwnerAuthentication, completion: completion)
    }catch let error as LocalAuthError {
      throw error
    }
  }
  
  
  // MARK: Private methods
  
  fileprivate func canEvaluatePolicy(_ policy: LAPolicy) throws{
    var error: NSError? = nil
    guard context.canEvaluatePolicy(policy, error: &error) else {
      throw LocalAuthError.system(message: error?.localizedDescription)
    }
  }
  
  // The completion block will be executed on the main thread.
  fileprivate func evaluatePolicy(_ policy: Int32, completion: @escaping (Bool)->()) throws {
    do{
      guard let policy = LAPolicy(rawValue: Int(policy)) else {
        throw LocalAuthError.unknown
      }
      
      try canEvaluatePolicy(policy)
      
      var authError: LocalAuthError? = nil
      if localizedReason == nil {
        localizedReason = "You need to authenticate in order to access the app's content.".localized
      }
      context.evaluatePolicy(policy, localizedReason: localizedReason!, reply: {(success, evaluateError) -> Void in
        if let error = evaluateError {
          authError =  LocalAuthError.system(message: error.localizedDescription)
        }
        DispatchQueue.main.async {
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
