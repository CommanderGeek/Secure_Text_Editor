import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import {MatInputModule} from '@angular/material/input';
import {MatFormFieldModule} from '@angular/material/form-field';
import {FormsModule} from '@angular/forms';
import {MatDividerModule} from '@angular/material/divider';
import {MatButtonModule} from '@angular/material/button';
import {MatIcon} from "@angular/material/icon";
import {EncryptionService} from "./EncryptionService";
import {MatOption} from "@angular/material/autocomplete";
import {MatSelect} from "@angular/material/select";
import {MatRadioButton, MatRadioGroup} from "@angular/material/radio";
import { CommonModule } from '@angular/common';
import {MatMenu} from "@angular/material/menu";
import { MatMenuModule} from '@angular/material/menu';
import {MatSidenavContainer, MatSidenavModule} from "@angular/material/sidenav";
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ReactiveFormsModule } from '@angular/forms';
import { ToastrService } from "ngx-toastr";
import {MatCheckbox} from "@angular/material/checkbox";

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    FormsModule, MatFormFieldModule, MatInputModule, MatDividerModule, MatButtonModule,
    MatIcon, MatOption, MatSelect, MatRadioGroup, MatRadioButton, CommonModule, MatMenu, MatMenuModule,
    MatSidenavContainer, MatSidenavModule, MatSnackBarModule, ReactiveFormsModule, MatCheckbox
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  title = 'secure-text-editor-ui';
  fileContent: string = '';  // This holds the text from the uploaded file
  encryptedContent: string = ''; // Holds the encrypted content
  selectedKeySize: string = '';
  selectedPasswordAlgorithm: string = '';
  selectedChaCha20Algorithm:string = '';
  selectedEncryptionType: string = '';
  selectedPadding: string = '';
  selectedBlockMode: string = '';
  submitted: boolean = false;
  fileName: string= '';
  key: string='';
  selectedMAC: string='';
  enableMAC: boolean = false;
  password: string = '';
  passwordError: string = '';
  hidePassword: boolean = true;
  enableSignature: boolean = false;
  selectedSignature: string = '';
  selectedDetection: string = '';


  noPaddingModes = ['GCM_SYM', 'CTS_SYM', 'OFB_SYM', 'CTR_SYM', 'CFB_SYM', 'ChaCha20_SYM', 'CCM_SYM'];
  constructor(private encryptionService: EncryptionService, private snackBar: MatSnackBar, private toastr:ToastrService) {


  }
  // Function that is triggered when a file is selected
  onFileSelected(event: any, isDecrypt: boolean = false) {
    console.log('You uploaded the file at: '+ new Date());
    let file = event.target.files[0];
    const reader = new FileReader();
    reader.onload = (e: any) => {
      const fileContent = e.target.result; // Store file content temporarily
      if (isDecrypt) {
        // Call the decryption service
        if(fileContent.indexOf(".") >= 0){
        this.encryptionService.decryptText(fileContent).subscribe({
            next: (decryptedText) => {
              this.toastr.success('Decryption successful');
              this.fileContent = decryptedText; // Update editor with decrypted text
              console.log(fileContent.length);
              console.log('The file was successfully decrypted: '+ new Date());            },
            error: (err) => {
              console.error('Decryption failed:', err);
              this.toastr.error('Decryption failed', 'Decryption Failure');
            }
          });
        }else {
          this.toastr.error('This does not seem to be an encrypted text, try upload "Plain Text"', );
        }

      } else {
        // If no decryption is needed, load the file content as is
        this.fileContent = fileContent; // Load the file content to the editor
        this.snackBar.open('File loaded without decryption.', 'Close', { duration: 3000 });
      }
      // Reset the file input to allow the same file to be uploaded again
      event.target.value = '';
    };

    reader.readAsText(file); // Read file content
  }

  // Encrypt the content by sending it to the backend
  encryptFileContent(): void {
    this.submitted = true;

    // Validate if the encryption option is selected
    if (!this.selectedEncryptionType) {
      this.toastr.warning('Please select an encryption type.');
      return;
    }

    // Validate if specific fields for the selected encryption type are filled
    if (this.selectedEncryptionType === 'AES_SYM' && (!this.selectedKeySize || !this.selectedPadding || !this.selectedBlockMode)) {
      this.toastr.warning('Please fill in all the fields for AES Symmetric encryption.');
      return;
    }

    if (this.selectedEncryptionType === 'AES_PAS' && !this.selectedPasswordAlgorithm) {
      this.toastr.warning('Please fill in the key length for AES Password-based encryption.');
      return;
    }

    if (this.selectedEncryptionType === 'ChaCha20_PAS' && !this.selectedKeySize) {
      this.toastr.warning('Please fill in the key length for ChaCha20 Password-based encryption.');
      return;
    }

    if (this.selectedMAC === '' && this.selectedEncryptionType !== 'AES_AEM'){
      console.log(this.selectedEncryptionType);
      this.toastr.info('MAC is not selected: There will not be a message authentication!');
    }

    if(this.selectedEncryptionType === 'PBE_PAS'){
      this.selectedKeySize = '128';
      this.selectedBlockMode = 'CBC';
      this.selectedPadding = 'PKCS7Padding_SYM';
    }

    const payload = {
      text: this.fileContent,
      encryptionType: this.selectedEncryptionType,
      keySize: this.selectedKeySize,
      passwordAlgorithm: this.selectedPasswordAlgorithm,
      chaCha20Algorithm: this.selectedChaCha20Algorithm,
      padding: this.selectedPadding,
      blockMode: this.selectedBlockMode,
      key: this.key,
      mac: this.selectedMAC,
      password: this.password,
      signatureType: this.selectedSignature
    };
    console.log(payload.signatureType)
    if('NoPadding_SYM' === payload.padding &&  !this.validateForAESNoPadding(payload.text, payload.blockMode)){

      this.toastr.error('The text length must be a multiple of 16 bytes for AES with NoPadding.');
      return;
    }else if(this.noPaddingModes.includes(payload.blockMode) && !this.validateBlocks(payload.text)){
      console.log(payload.text.length)
      this.toastr.error('The text length must be a at least 16 bytes for AES with '+payload.blockMode);
      return;
    }else{
      this.snackBar.open('Encrypting the payload!', 'Close', { duration: 3000 });
      this.encryptionService.encryptText(payload).subscribe({
        next: (encryptedData) => {
          this.encryptedContent = encryptedData;
          this.saveFile(this.encryptedContent);
        },
        error: (err) => {
          console.error('Encryption failed', err)
          alert('Encryption failed :( ');
        }
      });
    }

  }

  normalSave(): void {
    this.saveFile(this.fileContent); // Save the encrypted content
  }

  // Save the encrypted content to a file on the client's machine
  saveFile(content: string): void {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    if (this.fileName === ''){
      this.fileName  = 'encrypted-text.txt';
    }else if(!this.fileName.indexOf(".txt")){
      this.fileName += ".txt";
    }
    a.download = this.fileName; // Name of the saved file
    a.click();

    window.URL.revokeObjectURL(url); // Clean up the object URL
    this.toastr.success('Encryption successful');
  }
  validateBlocks(text: string): boolean{
    return text.length > 15;
  }
  validateForAESNoPadding(text: string, blockMode: string): boolean {
    // Allow NoPadding only for specific block modes


    // Check if block mode requires no padding
    if (this.noPaddingModes.includes(blockMode)) {
      return true;
    }
      if (text.length > 0) {
        const encoder = new TextEncoder();
        const textBytes = encoder.encode(text);
        return textBytes.length % 16 === 0; // Valid only if multiple of 16 bytes
      }
      return false; // Invalid if text is empty or doesn't meet criteria
  }

  isPaddingAllowed(blockMode: string): boolean {
    // Only allow other padding modes for ECB and CBC
    const allowedModes = ['ECB_SYM', 'CBC_SYM'];
    return allowedModes.includes(blockMode);
  }


  onBlockModeChange(): void {
    if (this.selectedBlockMode === 'GCM_SYM' || this.selectedBlockMode === 'CTS_SYM') {
      this.selectedPadding = 'NoPadding_SYM';
    }
  }

  generateKey(){
    if (this.selectedEncryptionType && this.selectedKeySize) {
      const payload = {
        encryptionType: this.selectedEncryptionType,
        keySize: this.selectedKeySize,
      };
      console.log(payload)
      this.encryptionService.generateKey(payload).subscribe({
        next: (keyText) => {
          this.toastr.success('key was successfully generated!');
          this.key = keyText; // Update editor with decrypted text
        },
        error: (err) => {
          console.error('Key generation failed:', err);
          this.toastr.error('Key generation failed', 'Key generation Failure');
        }
      });
    }else{
      this.toastr.warning("Please select an Algorithm and a key size!")
    }



  }
  // Clear the key field
  clearKey() {
    this.key = '';
  }

  clearAllFields(): void {
    this.encryptedContent = '';
    this.selectedKeySize = '';
    this.selectedPasswordAlgorithm = '';
    this.selectedChaCha20Algorithm = '';
    this.selectedPadding = '';
    this.selectedBlockMode = '';
    this.key = '';
    this.submitted = false;
  }


  onEncryptionTypeChange(): void {
    if (this.selectedEncryptionType === 'ChaCha20_SYM') {
      this.selectedKeySize = '256';
      this.clearAllFields();
    }else{
      this.clearAllFields();
      this.selectedKeySize = '';
      this.clearKey();
    }
  }

  AEMSelected():void{
    this.selectedKeySize = '256';
    this.selectedPadding = 'NoPadding_SYM';
    this.selectedEncryptionType = 'AES_AEM';
  }
  onMACEnableChange(): void {
    if (this.enableMAC) {
      this.enableSignature = false; // Disable signature if MAC is enabled
      this.selectedSignature = '';  // Clear signature selection
    }
  }

  validatePassword(): void {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d@$!%*?&]{12,32}$/;
    // Enforce maximum length
    if (this.password.length > 32) {
      this.password = this.password.substring(0, 32); // Truncate to 32 characters
    }
    if (!this.password.match(passwordRegex)) {
      this.passwordError =
        'Password must be between 12-32 characters long and include at least one lowercase letter, one uppercase letter, ' +
        'one digit, and one special character.';
    } else{
      this.passwordError = ''; // Clear error if password is valid
    }
  }

  clearPassword(): void {
    this.password = '';
    this.passwordError = '';
  }
// Add the method to toggle password visibility
  togglePasswordVisibility(): void {
    this.hidePassword = !this.hidePassword;
  }

  onSignatureEnableChange(): void {
    if (this.enableSignature) {
      this.enableMAC = false; // Disable MAC if Signature is enabled
      this.selectedMAC = '';  // Clear MAC selection
    }
  }
}
