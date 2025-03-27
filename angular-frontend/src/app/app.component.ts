import {Component} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {CommonModule, NgOptimizedImage} from "@angular/common";

@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.scss'],
    imports: [CommonModule],
})
export class AppComponent {
    title = 'SAML-HAR Investigation Tool';
    entries: Map<string, any[]> = new Map<string, any[]>();
    logs: any[] = [];
    timings  : { earliest: any, latest: any } = {earliest: null, latest: null};

    samlCallbackUrlSlug = 'api/security/saml/callback';
    loginUrlSlug = 'internal/security/login';

    hostnameCheckOutput = {
        loginDomain: '',
        callbackDomain: '',
        loginDomainMatchesCallbackDomain: false,
        loginDomainError: '',
        callbackDomainError: '',
    }

    samlCallbackWithResponse: {
        url: string,
        showContent: boolean,
        samlResponse: string,
        inResponseTo: string,
        claims: string,
        emailAddress: string
    }[] = [];

    importantURLPatterns = [
        this.samlCallbackUrlSlug,
        'internal/security/me',
        'api/core/capabilities',
        this.loginUrlSlug,
        '/login?'
    ];

    constructor(private http: HttpClient) {
    }

    onDragOver(event: DragEvent) {
        event.preventDefault();
    }

    onDrop(event: DragEvent) {
        event.preventDefault();
        const file = event.dataTransfer?.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                const harFile = e.target?.result;
                if (harFile) {
                    this.sendHarFile(harFile);
                }
            };
            reader.readAsText(file);

        }
    }

    sendHarFile(harFile: string | ArrayBuffer) {
        const url = 'http://localhost:3000/har'; // Replace with your Node.js endpoint
        const data = {harFile};

        this.http.post<{ importantEntriesMap: Map<string, any[]> }>(url, data).subscribe(
            (response) => {
                this.entries = new Map(Object.entries(response.importantEntriesMap));
                this.collectLogs();
                this.findEarliestAndLatestLogs();
                this.checkLoginDomainMatchesCallbackDomain();
                this.gatherSamlResponsesFromSamlCallbacks();
            }, error => {
                console.error('Error:', error);
            });
    }

    decodeBase64String() {
        const url = 'http://localhost:3000/decode-base64'; // Replace with your Node.js endpoint
        const data = {encodedStrings: this.samlCallbackWithResponse.map(entry => entry.samlResponse)};

        this.http.post<{ parsedObjects: { inResponseTo: string, claims: string, emailAddress: string }[] }>(url, data).subscribe(
            (response) => {
                response.parsedObjects.forEach((parsedObject, index) => {
                    this.samlCallbackWithResponse[index].inResponseTo = parsedObject.inResponseTo;
                    this.samlCallbackWithResponse[index].claims = JSON.stringify(parsedObject.claims, null, 2);
                    this.samlCallbackWithResponse[index].emailAddress = parsedObject.emailAddress;
                });
            },
            (error) => {
                console.error('Error:', error);
            }
        );
    }

    checkLoginDomainMatchesCallbackDomain() {
        const entryKeys = Array.from(this.entries.keys());
        const loginURLs = entryKeys.filter(key => key.includes(this.loginUrlSlug));
        const callbackURLs = entryKeys.filter(key => key.includes(this.samlCallbackUrlSlug));
        // parse the domain from the URL
        const loginHostnames = loginURLs.map(url => new URL(url).hostname);
        const callbackHostnames = callbackURLs.map(url => new URL(url).hostname);

        // check if all values in loginHostnames are the same
        const loginDomain = loginHostnames.every(hostname => hostname === loginHostnames[0]) ? loginHostnames[0] : null;
        this.hostnameCheckOutput.loginDomain = loginDomain ?? Array.from(new Set(loginHostnames)).join(', ');
        // check if all values in callbackHostnames are the same
        const callbackDomain = callbackHostnames.every(hostname => hostname === callbackHostnames[0]) ? callbackHostnames[0] : null;
        this.hostnameCheckOutput.callbackDomain = callbackDomain ?? Array.from(new Set(callbackHostnames)).join(', ');

        // If loginDomain is null, it means there are multiple different domains, log an error
        if (loginDomain === null && loginHostnames.length > 0) {
            this.hostnameCheckOutput.loginDomainError = 'Multiple different login domains found';
        }

        // If callbackDomain is null, it means there are multiple different domains, log an error
        if (callbackDomain === null && callbackHostnames.length > 0) {
            this.hostnameCheckOutput.callbackDomainError = 'Multiple different callback domains found';
        }

        if (loginDomain && callbackDomain) {
            this.hostnameCheckOutput.loginDomainMatchesCallbackDomain = loginDomain === callbackDomain;
        }
    }

    gatherSamlResponsesFromSamlCallbacks() {
        this.entries.forEach((value, key) => {
            if (key.includes(this.samlCallbackUrlSlug)) {
                value.forEach(entry => {
                    if (entry.request && entry.request.postData && entry.request.postData.text) {
                        const samlResponse = entry.request.postData.text.split('SAMLResponse=')[1];

                        this.samlCallbackWithResponse.push({
                            url: key,
                            showContent: false,
                            samlResponse: samlResponse,
                            inResponseTo: '',
                            claims: '',
                            emailAddress: ''
                        });
                    }
                });
            }
        });

        this.decodeBase64String()
    }

    collectLogs() {
        this.entries.forEach((value) => {
            this.logs.push(...value);
        });
    }

    findEarliestAndLatestLogs() {
        if (this.logs.length === 0) {
            this.timings = { earliest: null, latest: null };
        }

        let earliest = this.logs[0];
        let latest = this.logs[0];

        this.logs.forEach(log => {
            if (new Date(log.startedDateTime) < new Date(earliest.startedDateTime)) {
                earliest = log;
            }
            if (new Date(log.startedDateTime) > new Date(latest.startedDateTime)) {
                latest = log;
            }
        });

        this.timings = { earliest, latest };
    }

    copyToClipboard(date: string) {
        const text = new Date(date).toLocaleString('GMT', {
            timeZone: 'GMT',
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3,
            hour12: false
        }).replace(',', ' @');
        navigator.clipboard.writeText(text).then(() => {
            console.log('Text copied to clipboard');
        }).catch(err => {
            console.error('Could not copy text: ', err);
        });
    }

    // This is needed to prevent the Object from being tree-shaken
    protected readonly Object = Object;
}
