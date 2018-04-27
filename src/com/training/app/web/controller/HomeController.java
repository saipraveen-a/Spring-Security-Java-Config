package com.training.app.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;

@Controller
public class HomeController {

	@RequestMapping(value="/", method=RequestMethod.GET)
	public String defaultPage() {
		return "home";
	}

	@RequestMapping(value="/admin", method=RequestMethod.GET)
	public String privateHome() {
		return "privatePage";
	}

  @RequestMapping(value="/login", method=RequestMethod.GET)
  public ModelAndView login(@RequestParam(value = "error", required = false) String error,
                      @RequestParam(value = "logout", required = false) String logout) {

    ModelAndView model = new ModelAndView();
    if (error != null) {
      model.addObject("error", "Invalid username and password!");
    }

    if (logout != null) {
      model.addObject("msg", "You've been logged out successfully.");
    }
    model.setViewName("login");

    return model;
  }

	@RequestMapping(value="/welcome", method=RequestMethod.GET)
	public String welcome() {
		return "welcome";
	}

	@RequestMapping(value="/sessionTimeout", method=RequestMethod.GET)
	public String sessionTimeout() {
		return "welcome";
	}

	@RequestMapping(value = "/accessdenied", method = RequestMethod.GET)
	public ModelAndView accesssDenied(Principal user) {

		ModelAndView model = new ModelAndView();

		if (user != null) {
			model.addObject("msg", "Hi " + user.getName()
					+ ", you do not have permission to access this page!");
		} else {
			model.addObject("msg",
					"You do not have permission to access this page!");
		}

		model.setViewName("403");
		return model;

	}
}