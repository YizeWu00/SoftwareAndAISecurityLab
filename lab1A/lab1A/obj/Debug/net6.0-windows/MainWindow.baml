   M S B A M L   `   `   `  ����@  <lab1A, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullclr-namespace:lab1Alab1A  5   	       lab1A.MainWindow   5   	   W SPresentationCore, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   %localclr-namespace:lab1A     5   	   -   5          � Topmost$  False��5   	    � Title$ 	Wireshake��5	   	    � Icon$ /MainWindowIcon.jpeg��6   $	��500��5
   	   $
��1000��6   .��5      � .+�5   
   �� .+�5      �� 
���   �$��3q�6)   
����ح� �� CornerRadius$ 10��6T   $��60��6f   $��80��6r    �� Left$	 105��6}   
 �� Top$ 93��6�   ._�5      �� $��Welcome to Wireshake!��6   $��WrapWithOverflow=�69   $��times new roman)�6Y    �� TextAlignment$ Center=�5      $��Center=�60   5      5      &   System.Windows.Controls.DataGrid  5      -   5        $��dtgrid_devices��5   3      AutoGenerateColumns$ False��6      HeadersVisibility$
 None=�6a   	   GridLinesVisibility$
	 None=�6z   $	��272��5      $	 105��6$   $	 158��66   $	��775��6G   
   
IsReadOnly$

 True��5      ��5   I   ��    Columns 5      0  *System.Windows.Controls.DataGridTextColumn  5      ,  &System.Windows.Controls.DataGridColumn   Header$ device��6)   1  +System.Windows.Controls.DataGridBoundColumn   Binding 69   �� *device+   	CellStyle 5      �� 5       �� 
TargetType*  $System.Windows.Controls.DataGridCell"  6$   .�5   "   ��  �� Property �@��TextAlignment �� Value$ Center=�6L   -   5        5      5      5       5!      5"      5#      