import logging
import os
from smolagent import tool
import google.generativeai as genai
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


APPROVED_LICENSES = [
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "MPL-2.0",
]

@tool(name="libraries_io_license", description="Look up a dependency license using Libraries.io API")
def fetch_license_via_api(group: str, artifact: str, version: str) -> str:
    """This tool looks up and returns the license information for a Maven artifact using the Libraries.io API.
    It requires a Libraries.io API key set in the LIBRARIES_IO_API_KEY environment variable.
    Returns the normalized license name (e.g., 'MIT', 'Apache-2.0') or 'Unknown' if not found.

    Args:
        group: The group ID of the Maven artifact (e.g., 'org.apache.commons')
        artifact: The artifact ID of the Maven package (e.g., 'commons-lang3')
        version: The version of the artifact to check (e.g., '3.12.0')

    Returns:
        str: The normalized license name or 'Unknown' if the license can't be determined
    """
    api_key = os.getenv("LIBRARIES_IO_API_KEY")
    if not api_key:
        logging.warning("LIBRARIES_IO_API_KEY is not set")
        return "Unknown"
    url = f"https://libraries.io/api/Maven/{group}:{artifact}/{version}?api_key={api_key}"
    resp = requests.get(url, timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("normalized_licenses") or data.get("licenses") or "Unknown"
    logging.error("Libraries.io request failed: %s", resp.status_code)
    return "Unknown"


@tool(name="lookup_license_text", description="Retrieve license text from SPDX list")
def lookup_license_text(license_name: str) -> str:
    """This tool retrieves the full text of a license from the SPDX license list.
    It fetches the license text directly from the SPDX GitHub repository using the SPDX identifier.
    Returns empty string if the license text cannot be fetched.

    Args:
        license_name: The SPDX identifier of the license (e.g., 'MIT', 'Apache-2.0')

    Returns:
        str: The full text of the license, or empty string if not found
    """
    url = f"https://raw.githubusercontent.com/spdx/license-list-data/main/text/{license_name}.txt"
    resp = requests.get(url, timeout=10)
    if resp.status_code == 200:
        return resp.text
    logging.warning("Could not fetch SPDX text for %s", license_name)
    return ""


@tool(name="fetch_repo_license", description="Download LICENSE file from a URL")
def fetch_license_from_repo(url: str) -> str:
    """This tool downloads and returns the content of a LICENSE file from a given URL.
    It handles HTTP requests and returns the raw text content of the license file.
    Returns empty string if the URL is invalid or the file cannot be downloaded.

    Args:
        url: The direct URL to the LICENSE file (e.g., raw GitHub content URL)

    Returns:
        str: The content of the license file, or empty string if download fails
    """
    if not url:
        return ""
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.text
    except Exception as exc:
        logging.error("Failed to fetch license from %s: %s", url, exc)
    return ""


@tool(name="search_license_issues", description="Search GitHub for a package and find its license")
def search_license_issues(package_name: str) -> str:
    """This tool searches GitHub for a package and attempts to find its license information.
    It requires a GitHub API token set in the GITHUB_TOKEN environment variable.
    First searches for repositories matching the package name, then:
    1. Tries to get license information using GitHub's license API
    2. Falls back to searching for LICENSE/COPYING files in the repository

    Args:
        package_name: The name of the package to search for on GitHub

    Returns:
        str: A message containing either:
            - The found license information (e.g., "Found license for owner/repo: MIT")
            - List of found license files
            - Error message if no license is found or an error occurs
    """
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        logging.warning("GITHUB_TOKEN is not set")
        return "Could not search: GitHub token not configured"

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Search for the repository
    search_url = f"https://api.github.com/search/repositories?q={package_name}"
    try:
        search_resp = requests.get(search_url, headers=headers, timeout=10)
        search_resp.raise_for_status()
        repos = search_resp.json().get("items", [])

        if not repos:
            return f"No repositories found for {package_name}"

        # Check the most relevant repository
        repo = repos[0]
        repo_full_name = repo["full_name"]

        # Get repository license info
        license_url = f"https://api.github.com/repos/{repo_full_name}/license"
        license_resp = requests.get(license_url, headers=headers, timeout=10)

        if license_resp.status_code == 200:
            license_info = license_resp.json()
            return f"Found license for {repo_full_name}: {license_info['license']['spdx_id']}"
        else:
            # Try to fetch LICENSE file directly
            contents_url = f"https://api.github.com/repos/{repo_full_name}/contents"
            contents_resp = requests.get(contents_url, headers=headers, timeout=10)

            if contents_resp.status_code == 200:
                files = [f["name"].lower() for f in contents_resp.json()]
                license_files = [f for f in files if "license" in f or "copying" in f]

                if license_files:
                    return f"Found potential license file(s) in {repo_full_name}: {', '.join(license_files)}"

            return f"No license information found for {repo_full_name}"

    except requests.exceptions.RequestException as e:
        logging.error("GitHub API request failed: %s", e)
        return f"Error searching for license: {str(e)}"


def analyze_license_text(text: str) -> str:
    """This tool uses Google's Gemini LLM to analyze license texts for unusual or concerning clauses.
    It evaluates the license against common software license patterns and identifies any
    non-standard, restrictive, or potentially problematic clauses. Requires a Google API key
    set in the GOOGLE_API_KEY environment variable.

    Args:
        text: The complete text of the license to analyze

    Returns:
        str: Either 'OK' if the license contains only standard permissive clauses,
             or 'Unusual clause detected: <explanation>' if any concerning clauses are found,
             or an error message if analysis fails
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        logging.warning("GOOGLE_API_KEY not set")
        return "Could not analyze: Google API key not configured"

    genai.configure(api_key=api_key)

    prompt = (
        "You are an expert license auditor analyzing software licenses. "
        "Review the following license text carefully. "
        "If it contains only standard permissive clauses commonly found in software licenses, respond with exactly 'OK'. "
        "If you find any unusual, restrictive, or concerning clauses, respond with 'Unusual clause detected:' "
        "followed by a brief explanation of the concerning clauses.\n\n"
        "Consider:\n"
        "1. Usage restrictions\n"
        "2. Distribution limitations\n"
        "3. Patent claims\n"
        "4. Attribution requirements\n"
        "5. Warranty and liability terms\n\n"
        "License text to analyze:\n"
        f"{text}"
    )

    try:
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logging.error("License analysis failed: %s", e)
        return f"Error analyzing license: {str(e)}"
