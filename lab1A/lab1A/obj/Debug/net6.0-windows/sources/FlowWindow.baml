   M S B A M L   `   `   `  ����@  <lab1A, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null-clr-namespace:lab1A.sourceslab1A.sources  5   	       lab1A.sources.FlowWindow   5   	   W SPresentationCore, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=6.0.2.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=6.0.2.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   -localclr-namespace:lab1A.sources     5   	   -   5          � Title$  
FlowWindow��5
   	   $	��800��6   $
��1200��6)    � WindowState$ Normal=�66   .��5      � .+�5   
   �� .+�5      �� -   5         ��Name$ 	tb_filter��5      $��输入过滤...��6)   $	��950��68   $
��Left=�6D   
 �� Top$ 40��6_   $��Center=�6o    J� RenderTransformOrigin$ 0.5,0.5&�6�   .��5   -   .��5   *   5      &   System.Windows.Controls.DataGrid  5      -   5        $��
dg_packets��5         AutoGenerateColumns$ False��6)   "   VerticalScrollBarVisibility$ Visible=�5   )   $
��Left=�6O   $ 61��6j   $��Center=�6z   $	��400��6�   $	��950��6�      
IsReadOnly$
 True��5         GridLinesVisibility$ 
Horizontal=�5      	   HorizontalGridLinesBrush
	 �����
   CanUserAddRows$
 False��6Y   ��5      ��    	CellStyle 5!      �� 5"       �� 
TargetType*  $System.Windows.Controls.DataGridCell"  6   .�5#      -   5        5%         Columns 5'      0  *System.Windows.Controls.DataGridTextColumn  5(      ,  &System.Windows.Controls.DataGridColumn   Header$	 No.��6)      Width5  /System.Windows.Controls.DataGridLengthConverter$ 50 66   1  +System.Windows.Controls.DataGridBoundColumn   Binding 6A   ��  �� Path$ number�6c     5)      $
 Time��6)   $	 100 67    6D   �� *time+6_     5*      $ Source��6)   $	 150 69    6E   �� *source+6b     5+      $ Destination��6)   $	 150 6>    6J   �� *destination+6l     5,      $ Protocol��6)    6;   �� *
protocol+6Z     5-      $ Length��6)    69   �� *length+6V     5.      $
 Info��6)   $ * 67    6A   �� *info+6\    � 	Resources 50      ��%    58         RowStyle 59      �� 5:      row��)  #System.Windows.Controls.DataGridRow"  6)    �� Triggers 5;      �� 5<       �� Binding 6*   �� *
visibility+ �� Value
 Hidden6I   .a�5=   "   ��  �� Property � y� �� Value$ Hidden=�6?   6P   5>      �� 5?       6*   �� *
visibility+ Visible6I   .a�5@   "   ��  � y�$ Visible=�6?   6Q   5A      �� 5B       6*   �� *
visibility+ 	Collapsed6I   .a�5C   "   ��  � y�$ 	Collapsed=�6?   6S   5D      �5F      �� 5G       � �� 6;   �� *
background+6Z   5I      5K      �� 5L      $��30��6   $ 10��6%   $	��900��65    �� Orientation$ 
Horizontal=�6A   .+�5M      �� -   5         ��Name$ btn_StopCapture��5M      $��停止��62   6_   �� 5N      -   5        $ btn_RestartCapture��5N      $��重新开始��65   6g   5O      �� 5P      -   5        $ tb_raw_packet��5P       �� TextWrapping$
 Wrap=�6-   $	 466��6A   $
��Left=�6R   $	��234��6m   $	��Top=�6z   $	��950��6�   5Q      5R      5S      