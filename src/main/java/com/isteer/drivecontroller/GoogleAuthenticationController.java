package com.isteer.drivecontroller;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class GoogleAuthenticationController {

	@Value("${google.oauth.callback.uri}")
	private String redirectUrl;

	@Value("${google.secret.key.path}")
	private Resource clientSecret;

	@Value("${google.credentials.folder.path}")
	private Resource credentialFolder;

	@Value("${google.dummy.user.identifier}")
	private String userIdentifier;

	@Value("${google.application.name}")
	private String applicationName;

	@Value("${google.tempfile.path}")
	private String tempPath;

	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

	GoogleAuthorizationCodeFlow googleAuthorizationCodeFlow;

	@PostConstruct
	public void init() throws Exception {
		GoogleClientSecrets googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY,
				new InputStreamReader(clientSecret.getInputStream()));
		googleAuthorizationCodeFlow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY,
				googleClientSecrets, Arrays.asList(DriveScopes.DRIVE))
				.setDataStoreFactory(new FileDataStoreFactory(credentialFolder.getFile())).build();
	}

	@GetMapping("/signin")
	public void googleSign(HttpServletResponse response) throws Exception {
		GoogleAuthorizationCodeRequestUrl requestUrl = googleAuthorizationCodeFlow.newAuthorizationUrl();
		String url = requestUrl.setRedirectUri(redirectUrl).setAccessType("offline").build();
		response.sendRedirect(url);

	}

	@GetMapping("/home")
	public void homePage(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
			throws Exception {
		String authorizationToken = httpServletRequest.getParameter("code");
		if (authorizationToken == null) {
			httpServletResponse.sendRedirect("http://localhost:8080/signin");
		}
		saveToken(authorizationToken);
		httpServletResponse.sendRedirect("http://localhost:8080/welcomepage");
	}

	private void saveToken(String authorizationToken) throws IOException {
		GoogleTokenResponse response = googleAuthorizationCodeFlow.newTokenRequest(authorizationToken)
				.setRedirectUri(redirectUrl).execute();
		googleAuthorizationCodeFlow.createAndStoreCredential(response, userIdentifier);

	}

	@GetMapping("/")
	public void root(HttpServletResponse response) throws Exception {
		boolean isAuthenticated = false;
		Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
		if (credential != null) {
			boolean validToken = credential.refreshToken();
			if (validToken) {
				isAuthenticated = true;
			}
		}
		if (isAuthenticated) {
			response.sendRedirect("http://localhost:8080/welcomepage");
		} else {
			response.sendRedirect("http://localhost:8080/signin");
		}
	}

	@GetMapping("/welcomepage")
	public String welcomePage() {
		return "WELCOME TO HOME PAGE";
	}

	@GetMapping("/uploadFileInGoogleDrive")
	public void uploadFileInGoogleDrive(HttpServletResponse httpServletResponse,
			@RequestParam("file") MultipartFile multipartFile) throws Exception {
		try {
			Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
			Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName(applicationName).build();
			if (!findDublicateFile(multipartFile.getOriginalFilename(), drive)) {
				File file = new File();
				file.setName(multipartFile.getOriginalFilename());
				java.io.File tempFile = new java.io.File(tempPath + multipartFile.getOriginalFilename());
				multipartFile.transferTo(tempFile);
				FileContent fileContent = new FileContent(multipartFile.getContentType(), tempFile);
				File response = drive.files().create(file, fileContent).setFields("id").execute();
				tempFile.delete();
				httpServletResponse.getWriter().write(response.getId());
			} else {
				httpServletResponse.getWriter().write("File Name Already Exists");
			}
		} catch (GoogleJsonResponseException e) {
			httpServletResponse.getWriter().write(e.getStatusMessage());
		} catch (TokenResponseException e) {
			httpServletResponse.getWriter()
					.write(e.getDetails().getError() + "    " + e.getDetails().getErrorDescription());
		}
	}

	@GetMapping("/listOfFile")
	public Object getListOfFile() throws IOException {
		try {
			Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
			Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName(applicationName).build();
			FileList fileList = drive.files().list().setFields("files(thumbnailLink)").execute();
			return fileList.getFiles().stream().map(f -> f.getThumbnailLink()).toList();
		} catch (GoogleJsonResponseException e) {
			return Arrays.asList(e.getStatusMessage());
		} catch (TokenResponseException e) {
			return e.getDetails();
		}
	}

	@DeleteMapping("/deleteFileById/{fileId}")
	public Object deleteFile(@PathVariable String fileId) throws IOException {
		try {
			Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
			Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName(applicationName).build();
			drive.files().delete(fileId).execute();
			return "file deleted sucessfully";
		} catch (GoogleJsonResponseException e) {
			return e.getStatusMessage();
		} catch (TokenResponseException e) {
			return e.getDetails();
		}
	}

	@GetMapping("/createFolder/{folderName}")
	public Object createFolder(@PathVariable String folderName) throws IOException {
		try {
			Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
			Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName(applicationName).build();
			if (!findDublicateFile(folderName, drive)) {
				File file = new File();
				file.setName(folderName);
				file.setMimeType("application/vnd.google-apps.folder");
				drive.files().create(file).execute();
				return "Folder Created Sucessfully";
			} else {
				return "The Folder Name Already Exists";
			}
		} catch (GoogleJsonResponseException e) {
			return e.getStatusMessage();
		} catch (TokenResponseException e) {
			return e.getDetails();
		}
	}

	@GetMapping("/uplodaFileInFolder")
	public Object uploadFileInFolder(@RequestParam("file") MultipartFile multipartFile) throws IOException {
		try {
			Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
			Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName(applicationName).build();
			if (!findDublicateFile(multipartFile.getOriginalFilename(), drive)) {
				File file = new File();
				file.setName(multipartFile.getOriginalFilename());
				file.setParents(Arrays.asList("1mCX2mCzxHuvRxaPsNvXWPWDnWLb63khA"));
				java.io.File tempFile = new java.io.File(tempPath + multipartFile.getOriginalFilename());
				multipartFile.transferTo(tempFile);
				FileContent content = new FileContent(multipartFile.getContentType(), tempFile);
				File response = drive.files().create(file, content).setFields("id").execute();
				tempFile.delete();
				return response.getId();
			} else {
				return "FileName Already Exists";
			}
		} catch (GoogleJsonResponseException e) {
			return e.getStatusMessage();
		} catch (TokenResponseException e) {
			return e.getDetails();
		}
	}

	public boolean findDublicateFile(String fileName, Drive drive) throws IOException {
		String query = "name='" + fileName + "' and trashed=false";
		FileList fileList = drive.files().list().setQ(query).setFields("files(id)").execute();
		List<File> files = fileList.getFiles();
		if (files.isEmpty()) {
			return false;
		}
		return true;

	}
	
	@GetMapping("/getFileById/{fileId}")
	public void getFileById(@PathVariable String fileId,HttpServletResponse httpServletResponse) throws IOException {
		Credential credential = googleAuthorizationCodeFlow.loadCredential(userIdentifier);
		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
				.setApplicationName(applicationName).build();
		File response=drive.files().get(fileId).setFields("webViewLink").execute();
		httpServletResponse.sendRedirect(response.getWebViewLink());
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
