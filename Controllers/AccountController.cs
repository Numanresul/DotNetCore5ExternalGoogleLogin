using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Identity.Models;
using System.Threading.Tasks;
using System.Security.Claims;
using Identity.Email;
using System.ComponentModel.DataAnnotations;
using RestSharp;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Identity.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private UserManager<AppUser> userManager;
        private SignInManager<AppUser> signInManager;

        public AccountController(UserManager<AppUser> userMgr, SignInManager<AppUser> signinMgr)
        {
            userManager = userMgr;
            signInManager = signinMgr;
        }

        public IActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            Login login = new Login();
            login.ReturnUrl = returnUrl;
            return View(login);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(Login login)
        {
            if (ModelState.IsValid)
            {


              var logInResponse = await ExternalApiRequestForSignIn(login);
                if ((int)logInResponse.StatusCode == 200)// servisten olumlu dönmüştür bizde yoksa oluşturup içeri alcaz varsa direk alcaz.
                {
                    string normalizedEmail = "";
                    string normalizedUserName = "";
                    if (!login.Email.Contains("@"))
                    {
                        normalizedEmail = login.Email + "@firstabul.com";
                        normalizedUserName = login.Email;
                    }
                    else
                    {
                        normalizedEmail = login.Email;
                        normalizedUserName = login.Email.Split("@")[0];
                    }
                    AppUser user = new AppUser
                    {
                        Email = normalizedEmail,
                        UserName = normalizedUserName
                    };
                    AppUser appUser = await userManager.FindByEmailAsync(normalizedEmail);
                    if (appUser != null)
                    {
                        UserLoginInfo info = new UserLoginInfo("hh", "hh", "ll");
                        string[] userInfo = { login.Email, login.Email };
                        TempData["UserEmail"] = normalizedEmail;
                        TempData["UserName"] = normalizedUserName;
                       var identResult = await userManager.AddLoginAsync(user, info);
                       
                            await signInManager.SignInAsync(user, false);
                        return Redirect(login.ReturnUrl ?? "/");//View(userInfo);


                    }
                    else
                    {
                        UserLoginInfo info = new UserLoginInfo("hh", "hh", "ll");
                        string[] userInfo = { login.Email, login.Email };
                        IdentityResult identResult = await userManager.CreateAsync(user);
                        if (identResult.Succeeded)
                        {
                            identResult = await userManager.AddLoginAsync(user, info);
                            TempData["UserEmail"] = normalizedEmail;
                            TempData["UserName"] = normalizedUserName;
                            await signInManager.SignInAsync(user, false);
                                return View(userInfo);
                            
                        }
                        return AccessDenied();
                    }
                    

                }
                else
                {
                    ModelState.AddModelError(nameof(login.Email), "Login Failed: Invalid Email or password");
                }

               //AppUser appUser = await userManager.FindByEmailAsync(login.Email);
                //if (appUser != null)
                //{
                //    await signInManager.SignOutAsync();
                //    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(appUser, login.Password, false, true);
                //    if (result.Succeeded)
                //        return Redirect(login.ReturnUrl ?? "/");

                //    /*bool emailStatus = await userManager.IsEmailConfirmedAsync(appUser);
                //    if (emailStatus == false)
                //    {
                //        ModelState.AddModelError(nameof(login.Email), "Email is unconfirmed, please confirm it first");
                //    }*/

                //    /*if (result.IsLockedOut)
                //        ModelState.AddModelError("", "Your account is locked out. Kindly wait for 10 minutes and try again");*/

                //    if (result.RequiresTwoFactor)
                //    {
                //        return RedirectToAction("LoginTwoStep", new { appUser.Email, login.ReturnUrl });
                //    }
                //}
                //ModelState.AddModelError(nameof(login.Email), "Login Failed: Invalid Email or password");
            }
            return View(login);
        }

        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoStep(string email, string returnUrl)
        {
            var user = await userManager.FindByEmailAsync(email);

            var token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");

            EmailHelper emailHelper = new EmailHelper();
            bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoStep(TwoFactor twoFactor, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(twoFactor.TwoFactorCode);
            }

            var result = await signInManager.TwoFactorSignInAsync("Email", twoFactor.TwoFactorCode, false, false);
            if (result.Succeeded)
            {
                return Redirect(returnUrl ?? "/");
            }
            else
            {
                ModelState.AddModelError("", "Invalid Login Attempt");
                return View();
            }
        }


        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            string redirectUrl = Url.Action("GoogleResponse", "Account");
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(nameof(Login));

            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            string[] userInfo = { info.Principal.FindFirst(ClaimTypes.Name).Value, info.Principal.FindFirst(ClaimTypes.Email).Value };
            if (result.Succeeded)
                return View(userInfo);
            else
            {
                AppUser user = new AppUser
                {
                    Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
                    UserName = info.Principal.FindFirst(ClaimTypes.Surname).Value
                };


                IdentityResult identResult = await userManager.CreateAsync(user);
                if (identResult.Succeeded)
                {
                    identResult = await userManager.AddLoginAsync(user, info);
                    if (identResult.Succeeded)
                    {
                        await signInManager.SignInAsync(user, false);
                        return View(userInfo);
                    }
                }
                return AccessDenied();
            }
        }

        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required]string email)
        {
            if (!ModelState.IsValid)
                return View(email);

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
                return RedirectToAction(nameof(ForgotPasswordConfirmation));

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var link = Url.Action("ResetPassword", "Account", new { token, email = user.Email }, Request.Scheme);

            EmailHelper emailHelper = new EmailHelper();
            bool emailResponse = emailHelper.SendEmailPasswordReset(user.Email, link);

            if (emailResponse)
                return RedirectToAction("ForgotPasswordConfirmation");
            else
            {
                // log email failed 
            }
            return View(email);
        }

        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            if (!ModelState.IsValid)
                return View(resetPassword);

            var user = await userManager.FindByEmailAsync(resetPassword.Email);
            if (user == null)
                RedirectToAction("ResetPasswordConfirmation");

            var resetPassResult = await userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
            if (!resetPassResult.Succeeded)
            {
                foreach (var error in resetPassResult.Errors)
                    ModelState.AddModelError(error.Code, error.Description);
                return View();
            }

            return RedirectToAction("ResetPasswordConfirmation");
        }

        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        public async Task<IRestResponse> ExternalApiRequestForSignIn(Login login) 
        {

            var data = new JObject();
            data["email"] = login.Email;
            data["password"] = login.Password;
            string json = JsonConvert.SerializeObject(data);

            var client = new RestClient("https://service.firsatbull.com.tr/api/Auth/login");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            request.AddParameter("application/json", json, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            return response;
        }
    }
}