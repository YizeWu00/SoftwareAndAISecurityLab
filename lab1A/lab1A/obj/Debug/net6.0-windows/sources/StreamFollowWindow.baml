   M S B A M L   `   `   `  ����@  <lab1A, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null-clr-namespace:lab1A.sourceslab1A.sources  5   	   &     lab1A.sources.StreamFollowWindow   5   	   W SPresentationCore, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   -localclr-namespace:lab1A.sources     5   	   $	��823��5   	   $
��1173��6   .��5	      � .+�5
   
   �� .+�5      &   System.Windows.Controls.DataGrid  -   5           Name$  	dg_stream��5   0   $	��600��6   $	��800��6$      AutoGenerateColumns$ False��6[      HeadersVisibility$
 None=�6w      CanUserAddRows$ False��6�    �� Left$	 186��6�   
 �� Top$ 49��6�   $��Center=�6�   $	��Top=�6�      
IsReadOnly$
 True��5      ��5   C   ��    Columns 5      0  *System.Windows.Controls.DataGridTextColumn  5      ,  &System.Windows.Controls.DataGridColumn   Header$  ��6)   	   Width5  /System.Windows.Controls.DataGridLengthConverter$	 * 63   1  +System.Windows.Controls.DataGridBoundColumn
   Binding
 6=   �� *stream+6Z      RowStyle 5      �� 5      row�� �� 
TargetType)  #System.Windows.Controls.DataGridRow"  6)    �� Triggers 5      �� 5       �� Binding 6*   �� *
visibility+ �� Value
 Hidden6I   .a�5   "   ��  �� Property � y� �� Value$ Hidden=�6?   6P   5      �� 5       6*   �� *
visibility+ Visible6I   .a�5   "   ��  � y�$ Visible=�6?   6Q   5      �� 5       6*   �� *
visibility+ 	Collapsed6I   .a�5   "   ��  � y�$ 	Collapsed=�6?   6S   5      5       5#      5$      5%      5&      