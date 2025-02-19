import { Injectable } from '@angular/core';
import {HttpClient, HttpHeaders} from '@angular/common/http';
import {catchError, Observable, throwError} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {

  private apiEncrypt = '/api/encrypt';
  private apiDecrypt = '/api/decrypt';
  private apiGenerateKey = '/api/generate-key';
  private apiPBE = '/api/decrypt/pbe';
  private apiProtect = '/api/protect';
  private apiVerify = '/api/verify';

  constructor(private http: HttpClient) { }

  // Send the text and encryption parameters to the backend
  encryptText(payload: any): Observable<string> {
    const headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    console.log('Payload:', payload);
    return this.http.post(this.apiEncrypt, payload, { headers: headers, responseType: 'text' });
  }

  decryptText(payload: any): Observable<string> {
    return this.http.post(this.apiDecrypt, payload, { responseType: 'text' }).pipe(
      catchError(error => {
        if (error.status === 403) {
          return throwError(() => new Error('Message Compromised!'));
        } else if (error.status === 404) {
          return throwError(() => new Error('Metadata not found for the given file ID'));
        } else if (error.status === 400) {
          return throwError(() => new Error('Invalid input format for decryption'));
        } else {
          return throwError(() => new Error('Decryption failed: last block incomplete in decryption'));
        }
      })
    );
  }

  decryptPBE(payload: any): Observable<string> {
    return this.http.post(this.apiPBE, payload, { responseType: 'text' }).pipe(
      catchError(error => {
        if (error.status === 401) {
          return throwError(() => new Error('Wrong Password!'));
        } else if (error.status === 403) {
          return throwError(() => new Error('Message Compromised!'));
        } else if (error.status === 404) {
          return throwError(() => new Error('Metadata not found for the given file ID'));
        } else if (error.status === 400) {
          return throwError(() => new Error('Invalid input format for PBE decryption'));
        } else {
          return throwError(() => new Error('PBE Decryption failed: Ciphertext contains errors'));
        }
      })
    );
  }



  generateKey(request: any): Observable<string> {
    return this.http.post<string>(this.apiGenerateKey, request, { responseType: 'text' as 'json' });
  }

  protect(payload: any): Observable<string> {
    const headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    console.log('Payload:', payload);
    return this.http.post(this.apiProtect, payload, { headers: headers, responseType: 'text' });
  }

  verify(payload: any): Observable<string> {
    return this.http.post(this.apiVerify, payload, { responseType: 'text' }).pipe(
      catchError(error => {
        if (error.status === 403) {
          return throwError(() => new Error('Message Compromised!'));
        } else if (error.status === 404) {
          return throwError(() => new Error('Metadata not found for the given file ID'));
        } else if (error.status === 400) {
          return throwError(() => new Error('Invalid input format for verification'));
        } else {
          return throwError(() => new Error('Verification failed: Unknown error'));
        }
      })
    );
  }

}
