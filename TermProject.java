package com.src.project;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class Honey
 */
@WebServlet("/Honey")
public class TermProject extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */

	First first = new First();

	public TermProject() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		String method = request.getParameter("method");
		String message = request.getParameter("message");
		String key = request.getParameter("key");
		String outputText = null;
		HoneyEncryption enc1 = new HoneyEncryption();
		RSAEncryption enc2 = new RSAEncryption();
		String ERROR_MESSAGE = "Please enter the required fields";
		if (method.equalsIgnoreCase("Select") && message.equals("") && key.equals("")) {
			request.setAttribute("errorMessage", ERROR_MESSAGE);
			RequestDispatcher dispatcher = request.getRequestDispatcher("/First.jsp");
			dispatcher.forward(request, response);
		} else {
			if (method.equalsIgnoreCase("honey encryption")) {
				InputEncDec hEnc = new InputEncDec(key, method, message);
				if (request.getParameter("encrypt") != null) {
					outputText = "Cipher text: " + hEnc.encrypt(message, key) + " " + " original text: "
							+ hEnc.decrypt();

					request.setAttribute("outputText", outputText);
					// session.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/First.jsp");
					dispatcher.forward(request, response);
				}
				if (request.getParameter("decrypt") != null) {
					outputText = "Decrypted text: " + InputEncDec.checkForCorrectKey(message, key);
					// session.setAttribute("outputText", outputText);
					request.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/Second.jsp");
					dispatcher.forward(request, response);
				} else if (request.getParameter("compare") != null) {
					outputText = "Honey Encryption took " + enc1.calcExecutionTime()
							+ " seconds to encrypt and decrypt 1000 messages." + "\n" + " RSA Encryption took "
							+ enc2.calcExecutionTime() + " seconds to encrypt and decrypt 1000 messages";
					// session.setAttribute("outputText", outputText);
					request.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/First.jsp");
					dispatcher.forward(request, response);
				}

			} else if (method.equalsIgnoreCase("RSA")) {
				RSAEncDec encDec = new RSAEncDec(message);
				if (request.getParameter("encrypt") != null) {
					outputText = "Cipher text: " + encDec.encrypt(message) + " " + " original text: "
							+ encDec.decrypt();

					request.setAttribute("outputText", outputText);
					// session.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/First.jsp");
					dispatcher.forward(request, response);
				}
				if (request.getParameter("decrypt") != null) {
					outputText = "Decrypted text: " + encDec.wrongDecryption();
					// session.setAttribute("outputText", outputText);
					request.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/Second.jsp");
					dispatcher.forward(request, response);
				} else if (request.getParameter("compare") != null) {
					outputText = "Honey Encryption took " + enc1.calcExecutionTime()
							+ " seconds to encrypt and decrypt 1000 messages." + "\n" + " RSA Encryption took "
							+ enc2.calcExecutionTime() + " seconds to encrypt and decrypt 1000 messages";
					// session.setAttribute("outputText", outputText);
					request.setAttribute("outputText", outputText);
					RequestDispatcher dispatcher = request.getRequestDispatcher("/First.jsp");
					dispatcher.forward(request, response);
				}
			}
		}
	}
}
