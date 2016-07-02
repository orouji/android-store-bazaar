package com.soomla.store.billing.bazaar;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.soomla.SoomlaApp;
import com.soomla.SoomlaUtils;
import com.soomla.store.billing.IabHelper;
import com.soomla.store.billing.IabPurchase;
import com.soomla.store.events.UnexpectedStoreErrorEvent;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.TreeMap;

/**
 * @author vedi
 *         MJafar Mashhadi
 * @date 26/05/15, 02/06/16
 *         
 */
public class NivadBazaarVerification {

    private static final String URL_BASE = "https://api.nivad.io";
    private static final String API_BASE = URL_BASE + "/v1";
    private static final String URL_PURCHASE = API_BASE + "/billing/check/purchase";
    private static final String URL_SUBSCRIPTION = API_BASE + "/billing/check/subscription";

    private static final String TAG = "SOOMLA NivadBazaarVerification";

    private final IabPurchase purchase;
    private final String applicationId;
    private final String billingSecret;
    private final String mJWT;
    private final boolean verifyOnServerFailure;
    private String accessToken = null;

    private static NivadBazaarVerification instance = null;

    public static NivadBazaarVerification getInstance(String applicationId, String billingSecret) {
        boolean verifyOnServerFailure = connectionAvailable();
        return getInstance(applicationId, billingSecret, verifyOnServerFailure);
    }

    public static NivadBazaarVerification getInstance(String applicationId, String billingSecret, boolean verifyOnServerFailure) {
        if (instance == null) {
            instance = new NivadBazaarVerification(applicationId, billingSecret, verifyOnServerFailure);
        }
        return getInstance();
    }

    public static NivadBazaarVerification getInstance() {
        return instance;
    }

    private NivadBazaarVerification(String applicationId, String billingSecret, boolean verifyOnServerFailure) {
        if (TextUtils.isEmpty(applicationId) || TextUtils.isEmpty(billingSecret)) {
            SoomlaUtils.LogError(TAG, "Can't initialize NivadBazaarVerification. Missing params.");
            throw new IllegalArgumentException();
        }

        this.applicationId = applicationId;
        this.billingSecret = billingSecret;
        this.mJWT = "bearer " + generateJWT(applicationId, billingSecret);
        this.verifyOnServerFailure = verifyOnServerFailure;
    }

    public static boolean connectionAvailable() {
        Context context = SoomlaApp.getAppContext();
        try {
            ConnectivityManager conMgr = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo info = conMgr.getActiveNetworkInfo();
            return info != null && info.isConnected();
        } catch (SecurityException e) {
            SoomlaUtils.LogError(TAG, "Please add " +
                    "<uses-permission android:name=\"android.permission.ACCESS_NETWORK_STATE\"/>" +
                    " to your app manifest");
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private String generateJWT(String applicationId, String applicationSecret) {
        byte[] key = applicationSecret.getBytes();

        Map<String, Object> claims = new TreeMap<String, Object>();
        claims.put("aid", applicationId);
        claims.put("typ", "billing");

        JWTSigner.Options options = new JWTSigner.Options();
        options.setAlgorithm(Algorithm.HS256);
        return new JWTSigner(key).sign(claims, options);
    }

    private HttpResponse doVerifyPost(JSONObject jsonObject, boolean isSubscription) throws IOException {
        HttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost(isSubscription ? URL_SUBSCRIPTION : URL_PURCHASE);
        post.setHeader("Content-type", "application/json; charset=UTF-8");
        post.setHeader("Accept", "application/json");
        post.setHeader("Authorization", mJWT);

        String body = jsonObject.toString();
        post.setEntity(new StringEntity(body, "UTF8"));
        return client.execute(post);
    }

    public void verifyPurchase(IabPurchase purchase) {
        boolean verified = NivadBazaarVerification.this.verifyOnServerFailure;

        UnexpectedStoreErrorEvent.ErrorCode errorCode = UnexpectedStoreErrorEvent.ErrorCode.VERIFICATION_TIMEOUT;

        try {
            if (TextUtils.isEmpty(mJWT) || purchase == null) {
                throw new IllegalStateException();
            }

            String purchaseToken = purchase.getToken();
            boolean isSubscription = purchase.getItemType().equals(IabHelper.ITEM_TYPE_SUBS);

            if (purchaseToken != null) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("purchase_token", purchaseToken);
                // jsonObject.put("packageName", purchase.getPackageName());
                jsonObject.put(isSubscription ? "subscription_id" : "product_id", purchase.getSku());
                // jsonObject.put("accessToken", accessToken);
                SoomlaUtils.LogDebug(TAG, "purchase details: sku = " + purchase.getSku() + " token = " + purchaseToken);

                SharedPreferences prefs = SoomlaApp.getAppContext().
                        getSharedPreferences("store.verification.prefs", Context.MODE_PRIVATE);
                Map<String, ?> extraData = prefs.getAll();
                if (extraData != null && !extraData.keySet().isEmpty()) {
                    for (String key : extraData.keySet()) {
                        jsonObject.put(key, extraData.get(key));
                    }
                }

                HttpResponse resp = doVerifyPost(jsonObject, isSubscription);

                if (resp != null) {
                    int statusCode = resp.getStatusLine().getStatusCode();

                    StringBuilder stringBuilder = new StringBuilder();
                    InputStream inputStream = resp.getEntity().getContent();
                    Reader reader = new BufferedReader(new InputStreamReader(inputStream));
                    final char[] buffer = new char[1024];
                    int bytesRead;
                    while ((bytesRead = reader.read(buffer, 0, buffer.length)) > 0) {
                        stringBuilder.append(buffer, 0, bytesRead);
                    }
                    JSONObject resultJsonObject = new JSONObject(stringBuilder.toString());
                    if (statusCode >= 200 && statusCode <= 299) {
                        String purchaseState = resultJsonObject.getString("purchaseState");
                        SoomlaUtils.LogDebug(TAG, "purchase state is " + purchaseState);
                        if ("valid".equals(purchaseState) || "unknown".equals(purchaseState)) {
                            verified = true;
                        } else if ("invalid".equals(purchaseState)) {
                            verified = false;
                        } else {
                            SoomlaUtils.LogError(TAG, "Invalid response format");
                            // Server error, using default value
                        }
                        if (verified) {
                            errorCode = null;
                        } else {
                            errorCode = UnexpectedStoreErrorEvent.ErrorCode.VERIFICATION_FAIL;
                            SoomlaUtils.LogError(TAG, "Failed to verify transaction receipt. The user will not get what he just bought.");
                        }
                    } else {
                        SoomlaUtils.LogError(TAG, "An error occurred while trying to get receipt purchaseToken. " +
                            "Stopping the purchasing process for: " + purchase.getSku());
                    }
                } else {
                    SoomlaUtils.LogError(TAG, "Got null response");
                }
            } else {
                SoomlaUtils.LogError(TAG, "An error occurred while trying to get receipt purchaseToken. " +
                        "Stopping the purchasing process for: " + purchase.getSku());
            }
        } catch (JSONException e) {
            SoomlaUtils.LogError(TAG, "Cannot build up json for verification: " + e);
        } catch (IOException e) {
            SoomlaUtils.LogError(TAG, e.getMessage());
        }

        purchase.setServerVerified(verified);
        purchase.setVerificationErrorCode(errorCode);
    }

}
