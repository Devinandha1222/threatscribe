# How to Get IBM watsonx.ai Project ID and API Key

This guide will walk you through getting your IBM watsonx.ai credentials to use ThreatScribe with real AI-powered detection.

---

## 📋 Prerequisites

- IBM Cloud account (free tier available)
- Access to IBM watsonx.ai service

---

## 🚀 Step-by-Step Guide

### Step 1: Create IBM Cloud Account

1. Go to [IBM Cloud](https://cloud.ibm.com/)
2. Click **"Create an account"** (or log in if you have one)
3. Complete the registration process
4. Verify your email address

### Step 2: Access IBM watsonx.ai

1. Log in to [IBM Cloud Console](https://cloud.ibm.com/)
2. In the top search bar, search for **"watsonx.ai"**
3. Click on **"watsonx.ai"** from the results
4. Click **"Launch watsonx.ai"** or **"Get started"**

### Step 3: Create a Project

1. Once in watsonx.ai, click **"Projects"** in the left sidebar
2. Click **"New project"** button
3. Choose **"Create an empty project"**
4. Fill in the details:
   - **Name**: `ThreatScribe AI` (or any name you prefer)
   - **Description**: `AI-powered threat detection system`
   - **Storage**: Select or create a Cloud Object Storage instance
5. Click **"Create"**

### Step 4: Get Your Project ID

**Method 1: From Project Settings**
1. Open your project
2. Click on the **"Manage"** tab
3. Click on **"General"** in the left sidebar
4. You'll see **"Project ID"** - this is your `WATSONX_PROJECT_ID`
5. Copy this ID (it looks like: `12345678-1234-1234-1234-123456789abc`)

**Method 2: From URL**
1. When you're in your project, look at the browser URL
2. It will look like: `https://dataplatform.cloud.ibm.com/projects/YOUR-PROJECT-ID?context=wx`
3. The part after `/projects/` and before `?` is your Project ID

### Step 5: Get Your API Key

1. Go to [IBM Cloud API Keys](https://cloud.ibm.com/iam/apikeys)
2. Click **"Create"** button
3. Fill in the details:
   - **Name**: `ThreatScribe API Key`
   - **Description**: `API key for ThreatScribe threat detection`
4. Click **"Create"**
5. **IMPORTANT**: Copy the API key immediately - you won't be able to see it again!
6. Store it securely (this is your `WATSONX_API_KEY`)

### Step 6: Get the Service URL

The watsonx.ai service URL depends on your region:

- **US South (Dallas)**: `https://us-south.ml.cloud.ibm.com`
- **US East (Washington DC)**: `https://us-east.ml.cloud.ibm.com`
- **EU (Frankfurt)**: `https://eu-de.ml.cloud.ibm.com`
- **EU (London)**: `https://eu-gb.ml.cloud.ibm.com`
- **Japan (Tokyo)**: `https://jp-tok.ml.cloud.ibm.com`

To find your region:
1. Go to your IBM Cloud dashboard
2. Look at the top right corner for your region
3. Use the corresponding URL above

---

## 🔧 Configure ThreatScribe

### Update the .env File

1. Open `threatscribe/backend/.env`
2. Update the following values:

```bash
# Change DEMO_MODE to false
DEMO_MODE=false

# Add your credentials
WATSONX_API_KEY=your_api_key_here_from_step_5
WATSONX_PROJECT_ID=your_project_id_here_from_step_4
WATSONX_URL=https://us-south.ml.cloud.ibm.com  # or your region's URL
WATSONX_MODEL=ibm/granite-13b-instruct-v2
```

### Example Configuration

```bash
# Server Configuration
PORT=3001

# Demo Mode (set to false for real AI)
DEMO_MODE=false

# IBM watsonx.ai Configuration
WATSONX_API_KEY=AbCdEf123456789_YourActualAPIKeyHere
WATSONX_PROJECT_ID=12345678-1234-1234-1234-123456789abc
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL=ibm/granite-13b-instruct-v2

# IBM Bob QA Configuration
IBM_BOB_STRICT_MODE=true
```

### Restart the Server

After updating the .env file:

```powershell
# Stop the current server (Ctrl+C in the terminal)
# Then restart it
cd threatscribe/backend
node server.js
```

You should see:
```
🚀 Server running on http://localhost:3001
📊 Demo Mode: DISABLED  # <-- This should now say DISABLED
🤖 IBM Bob Strict Mode: ENABLED
```

---

## 🧪 Test Real AI Detection

Once configured, test with:

```powershell
cd threatscribe
.\test-demo.ps1
```

You should now see real AI analysis instead of mock responses!

---

## 💰 Pricing Information

### IBM watsonx.ai Pricing

- **Lite Plan** (Free):
  - Limited to 25,000 tokens per month
  - Good for testing and small projects
  - No credit card required

- **Standard Plan** (Pay-as-you-go):
  - $0.0005 per 1,000 input tokens
  - $0.0015 per 1,000 output tokens
  - Scales with usage

### Cost Estimation for ThreatScribe

Typical usage per CVE analysis:
- Input: ~500 tokens (CVE text + prompts)
- Output: ~1,500 tokens (analysis results)
- **Cost per CVE**: ~$0.003 (less than 1 cent)

For 1,000 CVEs per month:
- **Estimated cost**: ~$3/month

---

## 🔒 Security Best Practices

### Protect Your API Key

1. **Never commit .env to git**
   - Already in `.gitignore`
   - Double-check before pushing code

2. **Use environment variables in production**
   ```bash
   export WATSONX_API_KEY="your_key"
   export WATSONX_PROJECT_ID="your_project_id"
   ```

3. **Rotate keys regularly**
   - Create new API keys every 90 days
   - Delete old keys after rotation

4. **Use separate keys for dev/prod**
   - Development: One API key
   - Production: Different API key
   - Easier to track usage and revoke if needed

---

## 🐛 Troubleshooting

### Error: "Watsonx.ai credentials not configured"

**Solution**: Make sure:
1. `.env` file exists in `backend/` directory
2. `DEMO_MODE=false` is set
3. API key and Project ID are correct
4. Server was restarted after changing .env

### Error: "Unauthorized" or "Invalid API Key"

**Solution**:
1. Verify API key is correct (no extra spaces)
2. Check if API key is still active in IBM Cloud
3. Ensure API key has access to watsonx.ai service

### Error: "Project not found"

**Solution**:
1. Verify Project ID is correct
2. Ensure project exists in watsonx.ai
3. Check that API key has access to the project

### Error: "Region not available"

**Solution**:
1. Verify the WATSONX_URL matches your IBM Cloud region
2. Check if watsonx.ai is available in your region
3. Try a different region URL

---

## 📚 Additional Resources

- [IBM watsonx.ai Documentation](https://www.ibm.com/docs/en/watsonx-as-a-service)
- [IBM Cloud API Keys](https://cloud.ibm.com/docs/account?topic=account-userapikey)
- [watsonx.ai Pricing](https://www.ibm.com/products/watsonx-ai/pricing)
- [IBM Cloud Free Tier](https://www.ibm.com/cloud/free)

---

## ✅ Quick Checklist

Before running ThreatScribe with real AI:

- [ ] IBM Cloud account created
- [ ] watsonx.ai service accessed
- [ ] Project created in watsonx.ai
- [ ] Project ID copied
- [ ] API Key created and saved
- [ ] Region URL identified
- [ ] `.env` file updated with credentials
- [ ] `DEMO_MODE=false` set
- [ ] Server restarted
- [ ] Test script runs successfully

---

## 🎯 What You Get with Real AI

### Enhanced Detection:
- **Better semantic understanding** of threats
- **Adaptive learning** from context
- **More accurate** obfuscation detection
- **Fewer false positives**
- **Detailed reasoning** for each detection

### Production Features:
- Real-time threat analysis
- Custom model fine-tuning
- Advanced prompt engineering
- Scalable to thousands of CVEs
- Enterprise-grade reliability

---

**Need Help?** Check the [TESTING_GUIDE.md](./TESTING_GUIDE.md) for more examples and troubleshooting tips.

**Ready to detect threats with real AI!** 🛡️🤖