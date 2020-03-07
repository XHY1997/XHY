package xd.login.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import jodd.util.StringUtil;
import xd.login.service.LoginService;
import xd.utils.MD5Utils;
import xd.utils.ReqUtils;


/**
	 * @comment: 
	 * @param: 
	 * @author: 勒夏特列原理
	 * @date 2019年3月21日下午4:20:17
	 */
	@Controller
public class LoginController {
		
		private Logger logger = LogManager.getLogger(LoginController.class);
		@Resource
		public LoginService loginService ;
		/**
		 * @comment:用户登录方法 
		 * @author: 勒夏特列原理
		 * @date: 2019年3月21日下午4:50:57
		 */
		@RequestMapping("/login")
		public void userLogin(HttpServletRequest req,HttpServletResponse res) {
			String usname=req.getParameter("username");
			String pwd=req.getParameter("password");
			
			String result="";
			HttpSession session=req.getSession();
			if(StringUtil.isEmpty(usname)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'请输入用户名'}", res);
			}
			if(StringUtil.isEmpty(pwd)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'请输入用户名'}", res);
			}
			try {
				result=loginService.LoginByUsname(usname.trim(), MD5Utils.toMd5(pwd),session);
				System.out.println(MD5Utils.toMd5(pwd));
			} catch (Exception e) {
				e.printStackTrace();
				logger.error("LoginController--userLogin--调用LoginByUsname错误");
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'系统异常请联系管理员1'}", res);
				return;
			}
			
			ReqUtils.backing_out_jsonArray(result, res);
			return;
			
		}
		@RequestMapping("/mainPage_show")
		public String userLoginMainPage(HttpServletRequest req,HttpServletResponse res) {
			HttpSession ses=req.getSession(false);
			if(ses==null) {
				return "redirect:/index";
			}
			//查询标题
			Map<String, Object> resultMap=new HashMap<>();
			try {
				resultMap=loginService.querySysValue();
			} catch (Exception e) {
				e.printStackTrace();
				logger.error("LoginController--userLoginMainPage--调用loginService.querySysValue错误");
				return "404";
			}
			req.setAttribute("resultMap", resultMap);
			//查询 一级菜单
			List<Map<String, Object>> listMap=new ArrayList<>();
			try {
				listMap=loginService.queryOneMenus();
			} catch (Exception e) {
				logger.error("LoginController--userLoginMainPage--调用loginService.queryOneMenus错误");
				return "404";
			}
			req.setAttribute("menuOneList", listMap);
			
			return "mainPage";
 		}
		
		/**
		 * 修改密码的方法
		 */
		@RequestMapping("/updatePwd_index")
		public void updatePwd(HttpServletRequest req,HttpServletResponse res) {
			String oldPwd=req.getParameter("oldpwd");
			String newPwd=req.getParameter("newpwd");
			String vfPwd=req.getParameter("vfpwd");
			/**
			 * 判断用户是否在登录状态
			 */
			HttpSession session=req.getSession();
			if(session==null) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'登录超时,请重新登录'}", res);
				return ;
			}
			String usid=session.getAttribute("USID").toString();
			if(StringUtil.isEmpty(usid)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'登录超时,请重新登录'}", res);
				return ;
			}
			/**
			 *初始化校验密码
			 */
			if(StringUtil.isEmpty(oldPwd)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'请输入原来的密码'}", res);
				return ;
			}
			if(StringUtil.isEmpty(newPwd)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'请输入新密码的密码'}", res);
				return ;
			}
			if(StringUtil.isEmpty(vfPwd)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'请输入确认的密码'}", res);
				return ;
			}
			
			if(!newPwd.equals(vfPwd)) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'俩次密码输入不一致'}", res);
				return ;
			}
			/**
			 * 修改密码
			 */
			String  result="";
			try {
				result=loginService.updatePwdByUsid(MD5Utils.toMd5(oldPwd.trim()),MD5Utils.toMd5(newPwd).trim(),usid);
			} catch (Exception e) {
				e.printStackTrace();
				logger.error("LoginController--updatePwd--调用loginService.updatePwdByUsid错误");
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'系统异常请联系管理员'}", res);
				return;
			}
				ReqUtils.backing_out_jsonArray(result, res);
			
		}
		
		/**
		 * 退出平台
		 */
		@RequestMapping("/exit_login_users")
		public String exitLogin(HttpServletRequest req,HttpServletResponse res) {
			HttpSession session=req.getSession();
			session=null;
			
			return "redirect:/index.jsp";
			
		}
		/**
		 * 加载二级菜单
		 */
		@RequestMapping("/findSonMenuList")
		public void loadSonmenuList(HttpServletRequest req,HttpServletResponse res) {
			String muid=req.getParameter("id");
			List<Map<String, Object>> listMap=new ArrayList<>();
			try {
				listMap=loginService.querySonMenu(muid);
				System.out.println(listMap);
			} catch (Exception e) {e.printStackTrace();
			logger.error("LoginController--updatePwd--调用loginService.updatePwdByUsid错误");
			ReqUtils.backing_out_jsonArray(new ArrayList<>(), res);// TODO: handle exception
			return;
			}
			ReqUtils.backing_out_jsonArray(listMap, res);// TODO: handle exception
			return;
 		}
		@RequestMapping("/checkSession_index")
		public void checkSession(HttpServletRequest req,HttpServletResponse res) {
			HttpSession session=req.getSession(false);
			if(session==null) {
				ReqUtils.backing_out_jsonArray("{result:'500',msg:'登录超时'}", res);
				return;
			}
			ReqUtils.backing_out_jsonArray("123", res);
			return;
			
		}
			
		
}
