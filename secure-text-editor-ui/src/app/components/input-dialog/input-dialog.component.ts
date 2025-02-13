import { Component, Inject } from '@angular/core';
import {
  MatDialogRef,
  MAT_DIALOG_DATA,
  MatDialogContent,
  MatDialogActions,
  MatDialogModule
} from '@angular/material/dialog';
import {MatFormField, MatFormFieldModule} from "@angular/material/form-field";
import {FormsModule, ReactiveFormsModule} from "@angular/forms";
import {MatInputModule} from "@angular/material/input";
import {MatDividerModule} from "@angular/material/divider";
import {MatButtonModule} from "@angular/material/button";
import {MatIcon} from "@angular/material/icon";
import {MatOption} from "@angular/material/autocomplete";
import {MatSelect} from "@angular/material/select";
import {MatRadioButton, MatRadioGroup} from "@angular/material/radio";
import {CommonModule} from "@angular/common";
import {MatMenu, MatMenuModule} from "@angular/material/menu";
import {MatSidenavContainer, MatSidenavModule} from "@angular/material/sidenav";
import {MatSnackBarModule} from "@angular/material/snack-bar";
import {MatCheckbox} from "@angular/material/checkbox";

@Component({
  selector: 'app-input-dialog',
  standalone: true,
  templateUrl: './input-dialog.component.html',
  imports: [
    FormsModule, MatFormFieldModule, MatInputModule, MatDividerModule, MatButtonModule,
    MatIcon, MatOption, MatSelect, MatRadioGroup, MatRadioButton, CommonModule, MatMenu, MatMenuModule,
    MatSidenavContainer, MatSidenavModule, MatSnackBarModule, ReactiveFormsModule, MatCheckbox, MatDialogModule
  ],
  styleUrl: './input-dialog.component.scss'
})
export class InputDialogComponent {
  password: string = '';
  passwordError: string = '';
  hidePassword: boolean = true;

  constructor(
    public dialogRef: MatDialogRef<InputDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { title: string; placeholder: string }
  ) {}

  onCancel(): void {
    this.dialogRef.close();
  }

  onConfirm(): void {
    this.dialogRef.close(this.password);
  }

  clearPassword(): void {
    this.password = '';
    this.passwordError = '';
  }

  togglePasswordVisibility(): void {
    this.hidePassword = !this.hidePassword;
  }

}
