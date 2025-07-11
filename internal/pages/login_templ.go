// Code generated by templ - DO NOT EDIT.

// templ: version: v0.3.906
package pages

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

func Login(errorMessage string) templ.Component {
	return templruntime.GeneratedTemplate(func(templ_7745c5c3_Input templruntime.GeneratedComponentInput) (templ_7745c5c3_Err error) {
		templ_7745c5c3_W, ctx := templ_7745c5c3_Input.Writer, templ_7745c5c3_Input.Context
		if templ_7745c5c3_CtxErr := ctx.Err(); templ_7745c5c3_CtxErr != nil {
			return templ_7745c5c3_CtxErr
		}
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templruntime.GetBuffer(templ_7745c5c3_W)
		if !templ_7745c5c3_IsBuffer {
			defer func() {
				templ_7745c5c3_BufErr := templruntime.ReleaseBuffer(templ_7745c5c3_Buffer)
				if templ_7745c5c3_Err == nil {
					templ_7745c5c3_Err = templ_7745c5c3_BufErr
				}
			}()
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 1, "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Bintaro University Admission - Login</title><style>\n\t\t\t\t* {\n\t\t\t\t\tmargin: 0;\n\t\t\t\t\tpadding: 0;\n\t\t\t\t\tbox-sizing: border-box;\n\t\t\t\t}\n\n\t\t\t\tbody {\n\t\t\t\t\tfont-family: \"Segoe UI\", Tahoma, Geneva, Verdana, sans-serif;\n\t\t\t\t\tbackground: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n\t\t\t\t\tmin-height: 100vh;\n\t\t\t\t\tdisplay: flex;\n\t\t\t\t\tflex-direction: column;\n\t\t\t\t}\n\n\t\t\t\t.navbar {\n\t\t\t\t\tbackground: rgba(255, 255, 255, 0.1);\n\t\t\t\t\tbackdrop-filter: blur(10px);\n\t\t\t\t\tpadding: 1rem 0;\n\t\t\t\t\tbox-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);\n\t\t\t\t\tborder-bottom: 1px solid rgba(255, 255, 255, 0.2);\n\t\t\t\t}\n\n\t\t\t\t.navbar h1 {\n\t\t\t\t\ttext-align: center;\n\t\t\t\t\tcolor: #fff;\n\t\t\t\t\tfont-size: 2rem;\n\t\t\t\t\tfont-weight: 600;\n\t\t\t\t\tletter-spacing: 0.5px;\n\t\t\t\t\ttext-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);\n\t\t\t\t}\n\n\t\t\t\t.login-container {\n\t\t\t\t\tflex: 1;\n\t\t\t\t\tdisplay: flex;\n\t\t\t\t\tjustify-content: center;\n\t\t\t\t\talign-items: center;\n\t\t\t\t\tpadding: 2rem;\n\t\t\t\t}\n\n\t\t\t\t.login-card {\n\t\t\t\t\tbackground: rgba(255, 255, 255, 0.95);\n\t\t\t\t\tpadding: 3rem;\n\t\t\t\t\tborder-radius: 20px;\n\t\t\t\t\tbox-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);\n\t\t\t\t\tbackdrop-filter: blur(10px);\n\t\t\t\t\tborder: 1px solid rgba(255, 255, 255, 0.3);\n\t\t\t\t\twidth: 100%;\n\t\t\t\t\tmax-width: 400px;\n\t\t\t\t\ttransform: translateY(-20px);\n\t\t\t\t\tanimation: fadeInUp 0.8s ease-out;\n\t\t\t\t}\n\n\t\t\t\t@keyframes fadeInUp {\n\t\t\t\t\tfrom {\n\t\t\t\t\t\topacity: 0;\n\t\t\t\t\t\ttransform: translateY(30px);\n\t\t\t\t\t}\n\t\t\t\t\tto {\n\t\t\t\t\t\topacity: 1;\n\t\t\t\t\t\ttransform: translateY(-20px);\n\t\t\t\t\t}\n\t\t\t\t}\n\n\t\t\t\t.login-header {\n\t\t\t\t\ttext-align: center;\n\t\t\t\t\tmargin-bottom: 2rem;\n\t\t\t\t}\n\n\t\t\t\t.login-header h2 {\n\t\t\t\t\tcolor: #333;\n\t\t\t\t\tfont-size: 1.8rem;\n\t\t\t\t\tmargin-bottom: 0.5rem;\n\t\t\t\t}\n\n\t\t\t\t.login-header p {\n\t\t\t\t\tcolor: #666;\n\t\t\t\t\tfont-size: 0.9rem;\n\t\t\t\t}\n\n\t\t\t\t.error-alert {\n\t\t\t\t\tbackground: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);\n\t\t\t\t\tcolor: white;\n\t\t\t\t\tpadding: 1rem;\n\t\t\t\t\tborder-radius: 12px;\n\t\t\t\t\tmargin-bottom: 1.5rem;\n\t\t\t\t\tborder: 1px solid rgba(255, 255, 255, 0.2);\n\t\t\t\t\tbox-shadow: 0 4px 15px rgba(255, 107, 107, 0.2);\n\t\t\t\t\tdisplay: block;\n\t\t\t\t\tanimation: slideDown 0.4s ease-out;\n\t\t\t\t}\n\n\t\t\t\t@keyframes slideDown {\n\t\t\t\t\tfrom {\n\t\t\t\t\t\topacity: 0;\n\t\t\t\t\t\ttransform: translateY(-10px);\n\t\t\t\t\t}\n\t\t\t\t\tto {\n\t\t\t\t\t\topacity: 1;\n\t\t\t\t\t\ttransform: translateY(0);\n\t\t\t\t\t}\n\t\t\t\t}\n\n\t\t\t\t.error-alert .alert-icon {\n\t\t\t\t\tdisplay: inline-block;\n\t\t\t\t\tmargin-right: 0.5rem;\n\t\t\t\t\tfont-weight: bold;\n\t\t\t\t}\n\n\t\t\t\t.error-alert .alert-message {\n\t\t\t\t\tfont-size: 0.9rem;\n\t\t\t\t\tfont-weight: 500;\n\t\t\t\t}\n\n\t\t\t\t.form-group {\n\t\t\t\t\tmargin-bottom: 1.5rem;\n\t\t\t\t}\n\n\t\t\t\t.form-group label {\n\t\t\t\t\tdisplay: block;\n\t\t\t\t\tmargin-bottom: 0.5rem;\n\t\t\t\t\tcolor: #333;\n\t\t\t\t\tfont-weight: 500;\n\t\t\t\t\tfont-size: 0.9rem;\n\t\t\t\t}\n\n\t\t\t\t.form-group input {\n\t\t\t\t\twidth: 100%;\n\t\t\t\t\tpadding: 0.8rem 1rem;\n\t\t\t\t\tborder: 2px solid #e1e5e9;\n\t\t\t\t\tborder-radius: 12px;\n\t\t\t\t\tfont-size: 1rem;\n\t\t\t\t\ttransition: all 0.3s ease;\n\t\t\t\t\tbackground: rgba(255, 255, 255, 0.9);\n\t\t\t\t}\n\n\t\t\t\t.form-group input:focus {\n\t\t\t\t\toutline: none;\n\t\t\t\t\tborder-color: #667eea;\n\t\t\t\t\tbox-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);\n\t\t\t\t\ttransform: translateY(-1px);\n\t\t\t\t}\n\n\t\t\t\t.form-group input:hover {\n\t\t\t\t\tborder-color: #c1c7d0;\n\t\t\t\t}\n\n\t\t\t\t.login-btn {\n\t\t\t\t\twidth: 100%;\n\t\t\t\t\tpadding: 0.9rem;\n\t\t\t\t\tbackground: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n\t\t\t\t\tcolor: #fff;\n\t\t\t\t\tborder: none;\n\t\t\t\t\tborder-radius: 12px;\n\t\t\t\t\tfont-size: 1rem;\n\t\t\t\t\tfont-weight: 600;\n\t\t\t\t\tcursor: pointer;\n\t\t\t\t\ttransition: all 0.3s ease;\n\t\t\t\t\tbox-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);\n\t\t\t\t\tmargin-top: 1rem;\n\t\t\t\t}\n\n\t\t\t\t.login-btn:hover {\n\t\t\t\t\ttransform: translateY(-2px);\n\t\t\t\t\tbox-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);\n\t\t\t\t}\n\n\t\t\t\t.login-btn:active {\n\t\t\t\t\ttransform: translateY(0);\n\t\t\t\t}\n\n\t\t\t\t.link-below-form {\n\t\t\t\t\ttext-align: center;\n\t\t\t\t\tmargin-top: 1.5rem;\n\t\t\t\t}\n\n\t\t\t\t.link-below-form a {\n\t\t\t\t\tcolor: #667eea;\n\t\t\t\t\ttext-decoration: none;\n\t\t\t\t\tfont-size: 0.9rem;\n\t\t\t\t\ttransition: color 0.3s ease;\n\t\t\t\t}\n\n\t\t\t\t.link-below-form a:hover {\n\t\t\t\t\tcolor: #764ba2;\n\t\t\t\t\ttext-decoration: underline;\n\t\t\t\t}\n\n\t\t\t\t@media (max-width: 480px) {\n\t\t\t\t\t.login-card {\n\t\t\t\t\t\tpadding: 2rem;\n\t\t\t\t\t\tmargin: 1rem;\n\t\t\t\t\t}\n\t\t\t\t\t.navbar h1 {\n\t\t\t\t\t\tfont-size: 1.5rem;\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t</style></head><body><nav class=\"navbar\"><h1><a style=\"text-decoration: none; color: white\" href=\"/\">Bintaro University Admission</a></h1></nav><div class=\"login-container\"><div class=\"login-card\"><div class=\"login-header\"><h2>Login</h2></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if errorMessage != "" {
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 2, "<!-- Error Alert Section --> <div class=\"error-alert\" id=\"errorAlert\"><span class=\"alert-icon\">⚠</span> <span class=\"alert-message\" id=\"errorMessage\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var2 string
			templ_7745c5c3_Var2, templ_7745c5c3_Err = templ.JoinStringErrs(errorMessage)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `internal/pages/login.templ`, Line: 224, Col: 67}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var2))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 3, "</span></div>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		templ_7745c5c3_Err = templruntime.WriteString(templ_7745c5c3_Buffer, 4, "<form action=\"/login\" id=\"loginForm\" method=\"post\"><div class=\"form-group\"><label for=\"email\">Email Address</label> <input type=\"email\" id=\"email\" name=\"email\" required placeholder=\"Enter your email\"></div><div class=\"form-group\"><label for=\"password\">Password</label> <input type=\"password\" id=\"password\" name=\"password\" required placeholder=\"Enter your password\"></div><button type=\"submit\" class=\"login-btn\">Sign In</button></form><div class=\"link-below-form\"><a href=\"#\" onclick=\"showForgotPassword()\">Forgot your password?</a></div><div class=\"link-below-form\"><a href=\"/register\">Do not have any account?</a></div></div></div><script>\n\t\t\t\tfunction showForgotPassword() {\n\t\t\t\t\talert(\"Forgot password functionality would be implemented here.\");\n\t\t\t\t}\n\n\t\t\t\t// Add subtle animations to form inputs\n\t\t\t\tdocument.querySelectorAll(\"input\").forEach((input) => {\n\t\t\t\t\tinput.addEventListener(\"focus\", function () {\n\t\t\t\t\t\tthis.parentElement.style.transform = \"translateY(-2px)\";\n\t\t\t\t\t});\n\n\t\t\t\t\tinput.addEventListener(\"blur\", function () {\n\t\t\t\t\t\tthis.parentElement.style.transform = \"translateY(0)\";\n\t\t\t\t\t});\n\t\t\t\t});\n\n\t\t\t</script></body></html>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return nil
	})
}

var _ = templruntime.GeneratedTemplate
