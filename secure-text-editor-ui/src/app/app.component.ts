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

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, FormsModule, MatFormFieldModule, MatInputModule, MatDividerModule, MatButtonModule, MatIcon, MatOption, MatSelect, MatRadioGroup, MatRadioButton, CommonModule, MatMenu, MatMenuModule, MatSidenavContainer, MatSidenavModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  title = 'secure-text-editor-ui';
  fileContent: string = '';  // This will hold the text from the uploaded file
  encryptedContent: string = ''; // Holds the encrypted content
  selectedKeyLength: string = '128';
  selectedEncryptionMethod: string = 'symmetric'; // Default option
  selectedPasswordAlgorithm: string = '';
  selectedChaCha20Algorithm:string = '';
  selectedSignatureAlgorithm: string = 'SHA256withDSA';
  selectedEncryptionType: string = '';

  constructor(private encryptionService: EncryptionService) {}

  // Function that is triggered when a file is selected
  onFileSelected(event: any, isDecrypt: boolean = false) {
    const file = event.target.files[0];
    const reader = new FileReader();

    reader.onload = (e: any) => {
      this.fileContent = e.target.result; // Display file content in textarea
      if (isDecrypt) {
        //this.decryptFileContent(this.fileContent);
      }
    };

    reader.readAsText(file);
  }
  // Encrypt the content by sending it to the backend
  encryptFileContent(): void {
    console.log('Encrypting with:', this.selectedEncryptionType);
    this.encryptionService.encryptText(this.fileContent).subscribe({
      next: (encryptedData) => {
        this.encryptedContent = encryptedData;
        this.saveFile(this.encryptedContent); // Save the encrypted content
      },
      error: (err) => console.error('Encryption failed', err)
    });
  }

  // Save the encrypted content to a file on the client's machine
  saveFile(content: string): void {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);


    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted-text.txt'; // Name of the saved file
    a.click();

    window.URL.revokeObjectURL(url); // Clean up the object URL
  }
}
